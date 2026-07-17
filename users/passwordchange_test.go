package users

import (
	"testing"
	"time"

	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
)

// TestUpdatePasswordSetsPasswordChangedAt verifies that changing a password
// stamps the PasswordChangedAt timestamp so earlier tokens can be expired.
func TestUpdatePasswordSetsPasswordChangedAt(t *testing.T) {
	store, err := NewUserStore(&memorystorage.MockMemoryStorage{}, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}

	user, err := store.AddUser(User{Login: "john", Password: "initialPassword1!"})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}

	// a freshly created user hasn't changed their password yet
	if !user.PasswordChangedAt.IsZero() {
		t.Fatalf("expected PasswordChangedAt to be zero for a new user")
	}

	before := time.Now()
	if err := store.UpdatePassword(user.ID, "newPassword1!"); err != nil {
		t.Fatalf("update password error: %s", err)
	}
	after := time.Now()

	updated, err := store.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}

	if updated.PasswordChangedAt.IsZero() {
		t.Fatalf("expected PasswordChangedAt to be set after UpdatePassword")
	}

	changedAt := updated.PasswordChangedAt.UTC()
	if changedAt.Before(before.UTC().Add(-time.Second)) || changedAt.After(after.UTC().Add(time.Second)) {
		t.Fatalf("PasswordChangedAt %s not within the expected window [%s, %s]", changedAt, before.UTC(), after.UTC())
	}
}

// TestUpdatePasswordPersistsPasswordChangedAt verifies the timestamp survives a
// save/reload cycle (it is serialized to users.json).
func TestUpdatePasswordPersistsPasswordChangedAt(t *testing.T) {
	storage := &memorystorage.MockMemoryStorage{}
	store, err := NewUserStore(storage, 99)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}

	user, err := store.AddUser(User{Login: "john", Password: "initialPassword1!"})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}
	if err := store.UpdatePassword(user.ID, "newPassword1!"); err != nil {
		t.Fatalf("update password error: %s", err)
	}

	// reload from storage
	reloaded, err := NewUserStore(storage, 99)
	if err != nil {
		t.Fatalf("reload store error: %s", err)
	}
	reloadedUser, err := reloaded.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get reloaded user error: %s", err)
	}
	if reloadedUser.PasswordChangedAt.IsZero() {
		t.Fatalf("expected PasswordChangedAt to persist after reload")
	}
}
