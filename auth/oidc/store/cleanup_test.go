package oidcstore

import (
	"fmt"
	"testing"
	"time"

	"github.com/in4it/go-devops-platform/auth/oidc"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
)

// TestCleanupPendingStates: states without token are removed once they're
// older than PENDING_STATE_TTL, younger ones (logins in progress) are kept.
func TestCleanupPendingStates(t *testing.T) {
	store, err := NewStore(&memorystorage.MockMemoryStorage{})
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}
	store.OAuth2Data["young"] = oidc.OAuthData{ID: "young", OIDCProviderID: "prov-1", CreatedAt: time.Now().Add(-time.Minute)}
	store.OAuth2Data["young2"] = oidc.OAuthData{ID: "young2", OIDCProviderID: "prov-1", CreatedAt: time.Now().Add(-2 * time.Minute)}
	store.OAuth2Data["old"] = oidc.OAuthData{ID: "old", CreatedAt: time.Now().Add(-PENDING_STATE_TTL - time.Minute)}
	store.OAuth2Data["withtoken"] = oidc.OAuthData{ID: "withtoken", CreatedAt: time.Now().Add(-24 * time.Hour), Token: oidc.Token{AccessToken: "abc"}, Subject: "sub-1", OIDCProviderID: "prov-1", UserInfo: oidc.UserInfo{Email: "john@example.com"}}

	deleted := store.CleanupOAuth2DataForAllEntries()
	if deleted != 1 {
		t.Fatalf("expected 1 deleted entry, got %d", deleted)
	}
	if _, ok := store.GetOAuth2DataByKey("young"); !ok {
		t.Fatalf("pending login in progress was deleted")
	}
	if _, ok := store.GetOAuth2DataByKey("young2"); !ok {
		t.Fatalf("other pending login in progress was deleted")
	}
	if _, ok := store.GetOAuth2DataByKey("old"); ok {
		t.Fatalf("stale pending state was not deleted")
	}
	if _, ok := store.GetOAuth2DataByKey("withtoken"); !ok {
		t.Fatalf("entry with token was deleted")
	}
}

// TestPendingStatesCapped: unauthenticated users starting logins can't grow
// the store without bound.
func TestPendingStatesCapped(t *testing.T) {
	maxPendingStates := MAX_PENDING_STATES
	MAX_PENDING_STATES = 10
	defer func() { MAX_PENDING_STATES = maxPendingStates }()

	store, err := NewStore(&memorystorage.MockMemoryStorage{})
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}
	if err := store.SaveOAuth2Data(oidc.OAuthData{ID: "loggedin", CreatedAt: time.Now().Add(-time.Hour), Token: oidc.Token{AccessToken: "abc"}}, "loggedin"); err != nil {
		t.Fatalf("save error: %s", err)
	}
	start := time.Now().Add(-5 * time.Minute)
	for i := 0; i < 25; i++ {
		err := store.SaveOAuth2Data(oidc.OAuthData{ID: fmt.Sprintf("id-%d", i), CreatedAt: start.Add(time.Duration(i) * time.Second)}, fmt.Sprintf("state-%d", i))
		if err != nil {
			t.Fatalf("save error: %s", err)
		}
	}
	all := store.GetOAuth2DataCopy()
	if len(all) != MAX_PENDING_STATES+1 {
		t.Fatalf("expected %d entries, got %d", MAX_PENDING_STATES+1, len(all))
	}
	if _, ok := all["loggedin"]; !ok {
		t.Fatalf("entry with token was dropped")
	}
	if _, ok := all["state-24"]; !ok {
		t.Fatalf("newest pending state was dropped")
	}
	if _, ok := all["state-0"]; ok {
		t.Fatalf("oldest pending state was kept")
	}
}
