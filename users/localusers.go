package users

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (u *UserStore) AddUser(user User) (User, error) {
	if user.Login == "" {
		return user, fmt.Errorf("login cannot be empty")
	}
	existingUsers := u.ListUsers()
	for _, existingUser := range existingUsers {
		if existingUser.Login == user.Login {
			return User{}, fmt.Errorf("user with login '%s' already exists", user.Login)
		}
	}
	user.ID = uuid.NewString()
	if user.Password != "" {
		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			return user, fmt.Errorf("HashPassword error: %s", err)
		}
		user.Password = hashedPassword
	}
	u.Users = append(u.Users, user)
	if u.autoSave {
		return user, u.SaveUsers()
	}
	return user, nil
}

func (u *UserStore) AddUsers(users []User) ([]User, error) {
	createdUsers := []User{}
	existingUsers := u.ListUsers()
	for k := range users {
		for _, existingUser := range existingUsers {
			if existingUser.Login == users[k].Login {
				return createdUsers, fmt.Errorf("user with login '%s' already exists", users[k].Login)
			}
		}
		users[k].ID = uuid.NewString()
		if users[k].Password != "" {
			hashedPassword, err := HashPassword(users[k].Password)
			if err != nil {
				return createdUsers, fmt.Errorf("HashPassword error: %s", err)
			}
			users[k].Password = hashedPassword
		}
		u.Users = append(u.Users, users[k])
		existingUsers = append(existingUsers, users[k])
		createdUsers = append(createdUsers, users[k])
	}
	if u.autoSave {
		return createdUsers, u.SaveUsers()
	}
	return createdUsers, nil
}

func (u *UserStore) GetUserByID(id string) (User, error) {
	for _, user := range u.Users {
		if user.ID == id {
			user.Password = ""
			return user, nil
		}
	}
	return User{}, fmt.Errorf("User not found")
}

func (u *UserStore) GetUserByLogin(login string) (User, error) {
	for _, user := range u.Users {
		if user.Login == login {
			user.Password = ""
			return user, nil
		}
	}
	return User{}, fmt.Errorf("User not found")
}
func (u *UserStore) DeleteUserByLogin(login string) error {
	for k, user := range u.Users {
		if user.Login == login {
			u.Users = append(u.Users[:k], u.Users[k+1:]...)
			if u.autoSave {
				return u.SaveUsers()
			}
			return nil
		}
	}
	return fmt.Errorf("User not found")
}

func (u *UserStore) DeleteUserByID(id string) error {
	for k, user := range u.Users {
		if user.ID == id {
			u.Users = append(u.Users[:k], u.Users[k+1:]...)
			if u.autoSave {
				return u.SaveUsers()
			}
			return nil
		}
	}
	return fmt.Errorf("User not found")
}

// compareHashAndPassword can be replaced in tests
var compareHashAndPassword = bcrypt.CompareHashAndPassword

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// getDummyHash returns a bcrypt hash (at the current cost) that is used to compare
// against when the login doesn't exist, so that the response time doesn't reveal
// whether a user exists.
func getDummyHash() []byte {
	dummyHashOnce.Do(func() {
		hash, err := bcrypt.GenerateFromPassword([]byte(uuid.NewString()), passwordHashCost)
		if err != nil {
			panic(fmt.Sprintf("could not generate dummy bcrypt hash: %s", err))
		}
		dummyHash = hash
	})
	return dummyHash
}

func (u *UserStore) AuthUser(login, password string) (User, bool) {
	userIndex := -1
	for k, user := range u.Users {
		if user.Login == login {
			userIndex = k
			break
		}
	}
	if userIndex == -1 || u.Users[userIndex].Password == "" {
		// always run bcrypt, so that timing is similar for unknown users / users without password
		compareHashAndPassword(getDummyHash(), []byte(password))
		return User{}, false
	}
	user := u.Users[userIndex]
	if compareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return User{}, false
	}
	// upgrade hashes created with a lower cost
	if cost, err := bcrypt.Cost([]byte(user.Password)); err == nil && cost < passwordHashCost {
		if hashedPassword, err := HashPassword(password); err == nil {
			u.Users[userIndex].Password = hashedPassword
			user.Password = hashedPassword
			if u.autoSave {
				_ = u.SaveUsers() // login still succeeds if the upgraded hash can't be saved
			}
		}
	}
	return user, true
}

func (u *UserStore) LoginExists(login string) bool {
	for _, user := range u.Users {
		if user.Login == login {
			return true
		}
	}
	return false
}
func (u *UserStore) UpdateUser(user User) error {
	for k, existingUser := range u.Users {
		if existingUser.Login == user.Login {
			password := existingUser.Password // we keep the password
			user.Password = password
			u.Users[k] = user
			if u.autoSave {
				return u.SaveUsers()
			} else {
				return nil
			}
		}
	}
	return fmt.Errorf("user not found in database: %s", user.Login)
}

// UpdateUserByID updates the user with the given ID (the login can be changed). The password is kept.
func (u *UserStore) UpdateUserByID(user User) error {
	if user.ID == "" {
		return fmt.Errorf("user id cannot be empty")
	}
	if user.Login == "" {
		return fmt.Errorf("login cannot be empty")
	}
	for _, existingUser := range u.Users {
		if existingUser.ID != user.ID && existingUser.Login == user.Login {
			return fmt.Errorf("user with login '%s' already exists", user.Login)
		}
	}
	for k, existingUser := range u.Users {
		if existingUser.ID == user.ID {
			user.Password = existingUser.Password // we keep the password
			u.Users[k] = user
			if u.autoSave {
				return u.SaveUsers()
			}
			return nil
		}
	}
	return fmt.Errorf("user not found in database: userID %s", user.ID)
}
func (u *UserStore) UpdatePassword(userID string, password string) error {
	for k, existingUser := range u.Users {
		if existingUser.ID == userID {
			hashedPassword, err := HashPassword(password)
			if err != nil {
				return fmt.Errorf("HashPassword error: %s", err)
			}
			u.Users[k].Password = hashedPassword
			// Record when the password was changed so that auth tokens issued
			// before this moment can be expired (earlier sessions get logged out).
			u.Users[k].PasswordChangedAt = TimeOrEmpty(time.Now())
			if u.autoSave {
				return u.SaveUsers()
			} else {
				return nil
			}
		}
	}
	return fmt.Errorf("user not found in database: userID %s", userID)
}

const passwordHashCost = bcrypt.DefaultCost

func HashPassword(password string) (string, error) {
	adminPasswordHashed, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		return "", fmt.Errorf("unable to set password: %s", err)
	}
	return string(adminPasswordHashed), nil
}

func (u *UserStore) ListUsers() []User {
	users := make([]User, len(u.Users))
	for k, user := range u.Users {
		user.Password = ""
		users[k] = user
	}
	return users
}

func (u *UserStore) UserCount() int {
	return len(u.Users)
}

func (u *UserStore) Empty() error {
	u.Users = []User{}
	if u.autoSave {
		return u.SaveUsers()
	}
	return nil
}
