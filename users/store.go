package users

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/in4it/go-devops-platform/storage"
)

const USERSTORE_FILENAME = "users.json"

func NewUserStoreWithHooks(storage storage.Iface, maxUsers int, hooks UserHooks) (*UserStore, error) {
	userStore, err := NewUserStore(storage, maxUsers)
	if err != nil {
		return userStore, err
	}
	userStore.UserHooks = hooks
	return userStore, nil
}
func NewUserStore(storage storage.Iface, maxUsers int) (*UserStore, error) {
	userStore := &UserStore{
		autoSave: true,
		maxUsers: maxUsers,
		storage:  storage,
	}

	if !userStore.storage.FileExists(userStore.storage.ConfigPath(USERSTORE_FILENAME)) {
		userStore.Users = []User{}
		return userStore, nil
	}

	data, err := userStore.storage.ReadFile(userStore.storage.ConfigPath(USERSTORE_FILENAME))
	if err != nil {
		return userStore, fmt.Errorf("config read error: %s", err)
	}
	decoder := json.NewDecoder(bytes.NewBuffer(data))
	err = decoder.Decode(&userStore.Users)
	if err != nil {
		return userStore, fmt.Errorf("decode input error: %s", err)
	}
	return userStore, nil
}
