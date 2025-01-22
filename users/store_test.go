package users

import (
	"encoding/json"
	"testing"
	"time"

	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
)

func TestStorage(t *testing.T) {
	storage := &memorystorage.MockMemoryStorage{}

	users := []User{
		{
			Login: "testuser@domain.inv",
		},
	}
	userStoreBytes, err := json.Marshal(users)
	if err != nil {
		t.Fatalf("encode error: %s", err)
	}

	err = storage.WriteFile(storage.ConfigPath(USERSTORE_FILENAME), userStoreBytes)
	if err != nil {
		t.Fatalf("write error: %s", err)
	}

	store, err := NewUserStore(storage, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}

	listUsers := store.ListUsers()

	if len(listUsers) == 0 {
		t.Fatalf("no users found in userstore")
	}

}

func TestStorageEmptyLastLogin(t *testing.T) {
	storage := &memorystorage.MockMemoryStorage{}

	user1Time := "2025-01-22T11:33:12.20148-06:00"

	users := []map[string]string{}
	users = append(users, map[string]string{"login": "email@inv.inv", "lastLogin": ""})
	users = append(users, map[string]string{"login": "email2@inv.inv", "lastLogin": user1Time})

	userStoreBytes, err := json.Marshal(users)
	if err != nil {
		t.Fatalf("encode error: %s", err)
	}

	err = storage.WriteFile(storage.ConfigPath(USERSTORE_FILENAME), userStoreBytes)
	if err != nil {
		t.Fatalf("write error: %s", err)
	}

	store, err := NewUserStore(storage, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}

	listUsers := store.ListUsers()

	if len(listUsers) == 0 {
		t.Fatalf("no users found in userstore")
	}

	if !listUsers[0].LastLogin.IsZero() {
		t.Fatalf("user 0: time is not zero")
	}
	if time.Time(listUsers[1].LastLogin).Format("2006-01-02T15:04:05.999999Z07:00") != user1Time {
		t.Fatalf("user 1 time mismatch: %s vs %s", time.Time(listUsers[1].LastLogin).Format("2006-01-02T15:04:05.999999Z07:00"), user1Time)
	}
}
