package users

import (
	"testing"

	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordUsesDefaultCost(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword error: %s", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt cost error: %s", err)
	}
	if cost < bcrypt.DefaultCost {
		t.Fatalf("expected cost >= %d, got %d", bcrypt.DefaultCost, cost)
	}
}

func TestAuthUserLegacyMinCostHashAndRehash(t *testing.T) {
	storage := &memorystorage.MockMemoryStorage{}
	store, err := NewUserStore(storage, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}
	legacyHash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash error: %s", err)
	}
	store.Users = append(store.Users, User{ID: "1", Login: "legacy", Password: string(legacyHash)})

	if _, ok := store.AuthUser("legacy", "wrong"); ok {
		t.Fatalf("expected wrong password to fail")
	}
	if store.Users[0].Password != string(legacyHash) {
		t.Fatalf("hash should not be changed after a failed login")
	}
	if _, ok := store.AuthUser("legacy", "secret"); !ok {
		t.Fatalf("expected legacy MinCost hash to verify")
	}
	cost, err := bcrypt.Cost([]byte(store.Users[0].Password))
	if err != nil {
		t.Fatalf("bcrypt cost error: %s", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("expected hash to be upgraded to cost %d, got %d", bcrypt.DefaultCost, cost)
	}
	// upgraded hash is persisted
	reloaded, err := NewUserStore(storage, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}
	if _, ok := reloaded.AuthUser("legacy", "secret"); !ok {
		t.Fatalf("expected login to work with persisted upgraded hash")
	}
	cost, err = bcrypt.Cost([]byte(reloaded.Users[0].Password))
	if err != nil {
		t.Fatalf("bcrypt cost error: %s", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("expected persisted hash with cost %d, got %d", bcrypt.DefaultCost, cost)
	}
}

func TestAuthUserUnknownUserRunsBcrypt(t *testing.T) {
	calls := 0
	orig := compareHashAndPassword
	compareHashAndPassword = func(hash, password []byte) error {
		calls++
		return orig(hash, password)
	}
	defer func() { compareHashAndPassword = orig }()

	store, err := NewUserStore(&memorystorage.MockMemoryStorage{}, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}
	if _, err := store.AddUser(User{Login: "john", Password: "secret"}); err != nil {
		t.Fatalf("add user error: %s", err)
	}
	if _, err := store.AddUser(User{Login: "oidcuser"}); err != nil {
		t.Fatalf("add user error: %s", err)
	}

	for _, login := range []string{"unknown", "oidcuser"} {
		calls = 0
		if _, ok := store.AuthUser(login, "secret"); ok {
			t.Fatalf("expected auth to fail for %s", login)
		}
		if calls != 1 {
			t.Fatalf("expected bcrypt compare to run once for %s, got %d", login, calls)
		}
	}
	calls = 0
	if _, ok := store.AuthUser("john", "secret"); !ok {
		t.Fatalf("expected auth to succeed")
	}
	if calls != 1 {
		t.Fatalf("expected bcrypt compare to run once, got %d", calls)
	}
}
