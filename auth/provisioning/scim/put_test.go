package scim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/in4it/go-devops-platform/storage"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

func newScimForPut(t *testing.T) (*Scim, *int, *int) {
	t.Helper()
	disableCalls, reactivateCalls := 0, 0
	storage_ := &memorystorage.MockMemoryStorage{}
	userStore, err := users.NewUserStoreWithHooks(storage_, USERSTORE_MAX_USERS, users.UserHooks{
		DisableFunc: func(storage.Iface, users.User) error {
			disableCalls++
			return nil
		},
		ReactivateFunc: func(storage.Iface, users.User) error {
			reactivateCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("cannot create new user store: %s", err)
	}
	return New(storage_, userStore, "token"), &disableCalls, &reactivateCalls
}

func putUser(t *testing.T, s *Scim, id string, payload PostUserRequest) *httptest.ResponseRecorder {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("cannot marshal payload: %s", err)
	}
	req := httptest.NewRequest("PUT", fmt.Sprintf("http://example.com/api/scim/v2/Users/%s", id), bytes.NewBuffer(payloadBytes))
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.PutUserHandler(w, req)
	return w
}

func TestPutUserRename(t *testing.T) {
	s, disableCalls, _ := newScimForPut(t)
	user, err := s.UserStore.AddUser(users.User{Login: "john@domain.inv", Role: "user", Provisioned: true, Password: "secret"})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}
	w := putUser(t, s, user.ID, PostUserRequest{UserName: "john.doe@domain.inv", Active: false})
	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	updated, err := s.UserStore.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}
	if updated.Login != "john.doe@domain.inv" {
		t.Fatalf("expected user to be renamed, got %s", updated.Login)
	}
	if !updated.Suspended {
		t.Fatalf("expected user to be suspended")
	}
	if *disableCalls != 1 {
		t.Fatalf("expected disable hook to be called once, got %d", *disableCalls)
	}
	if s.UserStore.LoginExists("john@domain.inv") {
		t.Fatalf("old login should not exist anymore")
	}
	if s.UserStore.UserCount() != 1 {
		t.Fatalf("expected 1 user, got %d", s.UserStore.UserCount())
	}
	if _, ok := s.UserStore.AuthUser("john.doe@domain.inv", "secret"); !ok {
		t.Fatalf("expected password to be kept after rename")
	}
}

func TestPutUserRenameToExistingLogin(t *testing.T) {
	s, disableCalls, _ := newScimForPut(t)
	user, err := s.UserStore.AddUser(users.User{Login: "john@domain.inv", Role: "user", Provisioned: true})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}
	_, err = s.UserStore.AddUser(users.User{Login: "jane@domain.inv", Role: "user", Provisioned: true})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}
	w := putUser(t, s, user.ID, PostUserRequest{UserName: "jane@domain.inv", Active: false})
	if w.Code != 409 {
		t.Fatalf("expected status 409, got %d: %s", w.Code, w.Body.String())
	}
	if *disableCalls != 0 {
		t.Fatalf("disable hook should not run when validation fails")
	}
	unchanged, err := s.UserStore.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}
	if unchanged.Login != "john@domain.inv" || unchanged.Suspended {
		t.Fatalf("user should be unchanged: %+v", unchanged)
	}
}

func TestPutUserReactivate(t *testing.T) {
	s, _, reactivateCalls := newScimForPut(t)
	user, err := s.UserStore.AddUser(users.User{Login: "john@domain.inv", Role: "user", Provisioned: true, Suspended: true})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}
	w := putUser(t, s, user.ID, PostUserRequest{UserName: "john@domain.inv", Active: true})
	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if *reactivateCalls != 1 {
		t.Fatalf("expected reactivate hook to be called once, got %d", *reactivateCalls)
	}
	updated, err := s.UserStore.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}
	if updated.Suspended {
		t.Fatalf("expected user to be active")
	}
}
