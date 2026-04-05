package oidcstore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/in4it/go-devops-platform/auth/oidc"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
)

func TestGetJwksRefetchesExpiredCache(t *testing.T) {
	hits := 0
	newKid := "new-key"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		jwksKeys := oidc.Jwks{Keys: []oidc.JwksKey{{Kid: newKid, Kty: "RSA"}}}
		out, err := json.Marshal(jwksKeys)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}
		w.Write(out)
	}))
	defer ts.Close()

	store, err := NewStore(&memorystorage.MockMemoryStorage{})
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}

	uri := ts.URL + "/jwks.json"

	// Seed cache with expired entry that should be ignored.
	store.JwksCache[uri] = oidc.JwksCache{
		Expiration: time.Now().Add(-1 * time.Minute),
		Jwks:       oidc.Jwks{Keys: []oidc.JwksKey{{Kid: "old-key", Kty: "RSA"}}},
	}

	jwks, err := store.GetJwks(uri)
	if err != nil {
		t.Fatalf("get jwks error: %s", err)
	}

	if hits == 0 {
		t.Fatalf("expected expired cache to trigger network fetch")
	}

	if len(jwks.Keys) == 0 {
		t.Fatalf("jwks is empty")
	}

	if jwks.Keys[0].Kid != newKid {
		t.Fatalf("expected jwks kid %q, got %q", newKid, jwks.Keys[0].Kid)
	}
}
