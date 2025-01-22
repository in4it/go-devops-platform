package users

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalUser(t *testing.T) {
	// empty last login
	var user User
	payload := []byte(`{"id": "", "login": "testuser", "password": "tttt213", "role": "user", "oidcID": "", "samlID": "", "lastLogin": "", "provisioned": false, "role":"user","samlID":"","suspended":false}`)

	err := json.Unmarshal(payload, &user)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if !user.LastLogin.IsZero() {
		t.Fatalf("expected zero last login")
	}
	out, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if !strings.Contains(string(out), `"lastLogin":"0001-01-01T00:00:00Z"`) {
		t.Fatalf("expected date string in out: %s", out)
	}

	// missing last login
	user = User{}
	payload = []byte(`{"id": "", "login": "testuser", "password": "tttt213", "role": "user", "oidcID": "", "samlID": "", "provisioned": false, "role":"user","samlID":"","suspended":false}`)

	err = json.Unmarshal(payload, &user)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if !user.LastLogin.IsZero() {
		t.Fatalf("expected zero last login")
	}
	out, err = json.Marshal(user)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if !strings.Contains(string(out), `"lastLogin":"0001-01-01T00:00:00Z"`) {
		t.Fatalf("expected date string in out: %s", out)
	}
	// has last login
	user = User{}
	payload = []byte(`{"id": "", "login": "testuser", "password": "tttt213", "role": "user", "oidcID": "", "samlID": "", "lastLogin": "2025-01-22T11:33:12.20148-06:00", "provisioned": false, "role":"user","samlID":"","suspended":false}`)

	err = json.Unmarshal(payload, &user)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if user.LastLogin.IsZero() {
		t.Fatalf("expected non-zero last login")
	}
	out, err = json.Marshal(user)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if !strings.Contains(string(out), `"lastLogin":"2025-01-22T11:33:12.20148-06:00"`) {
		t.Fatalf("expected date string in out: %s", out)
	}

}
