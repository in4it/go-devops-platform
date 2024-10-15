package rest

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

func TestCreateUser(t *testing.T) {
	// first create a new user
	storage := &memorystorage.MockMemoryStorage{}

	c, err := newContext(storage, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("Cannot create context")
	}

	err = c.UserStore.Empty()
	if err != nil {
		t.Fatalf("Cannot create context")
	}

	// create a user
	payload := []byte(`{"id": "", "login": "testuser", "password": "tttt213", "role": "user", "oidcID": "", "samlID": "", "lastLogin": "", "provisioned": false, "role":"user","samlID":"","suspended":false}`)
	req := httptest.NewRequest("POST", "http://example.com/users", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	c.usersHandler(w, req)

	resp := w.Result()

	if resp.StatusCode != 200 {
		t.Fatalf("status code is not 200: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	var user users.User
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		t.Fatalf("Cannot decode response from create user: %s", err)
	}

}
