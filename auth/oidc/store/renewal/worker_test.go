package oidcrenewal

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/in4it/go-devops-platform/auth/oidc"
	oidcstore "github.com/in4it/go-devops-platform/auth/oidc/store"
	"github.com/in4it/go-devops-platform/storage"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

func fakeAccessToken(t *testing.T, exp time.Time) string {
	t.Helper()
	payload, err := json.Marshal(jwtExp{Expiration: exp.Unix()})
	if err != nil {
		t.Fatalf("marshal error: %s", err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func newTestRenewal(t *testing.T, tokenEndpointStatus int) (*Renewal, *httptest.Server) {
	t.Helper()
	return newTestRenewalWithTokenResponse(t, tokenEndpointStatus, `{"error": "invalid_grant"}`)
}

func newTestRenewalWithTokenResponse(t *testing.T, tokenEndpointStatus int, tokenResponse string) (*Renewal, *httptest.Server) {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery.json":
			out, _ := json.Marshal(oidc.Discovery{Issuer: "test-issuer", TokenEndpoint: ts.URL + "/token"})
			w.Write(out)
		case "/token":
			w.WriteHeader(tokenEndpointStatus)
			w.Write([]byte(tokenResponse))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	storage := &memorystorage.MockMemoryStorage{}
	store, err := oidcstore.NewStore(storage)
	if err != nil {
		t.Fatalf("new store error: %s", err)
	}
	userStore, err := users.NewUserStore(storage, 100)
	if err != nil {
		t.Fatalf("new user store error: %s", err)
	}
	return &Renewal{
		oidcStore:     store,
		enabled:       true,
		oidcProviders: []oidc.OIDCProvider{{ID: "prov-1", ClientID: "client", ClientSecret: "secret", DiscoveryURI: ts.URL + "/discovery.json"}},
		userStore:     userStore,
		renewalTime:   time.Hour,
		storage:       storage,
	}, ts
}

// TestWorkerDisablesUserOnRenewalFailure: when token renewal fails for the last
// time, the background worker disables the user's connections.
func TestWorkerDisablesUserOnRenewalFailure(t *testing.T) {
	backoffSleep = func() {}
	r, _ := newTestRenewal(t, http.StatusBadRequest)

	var mu sync.Mutex
	disabled := []string{}
	r.userStore.UserHooks.DisableFunc = func(_ storage.Iface, user users.User) error {
		mu.Lock()
		defer mu.Unlock()
		disabled = append(disabled, user.ID)
		return nil
	}
	user, err := r.userStore.AddUser(users.User{Login: "john@example.com", OIDCID: "oidc-1"})
	if err != nil {
		t.Fatalf("add user error: %s", err)
	}
	err = r.oidcStore.SaveOAuth2Data(oidc.OAuthData{
		ID:               "oidc-1",
		OIDCProviderID:   "prov-1",
		CreatedAt:        time.Now().Add(-2 * time.Hour),
		LastTokenRenewal: time.Now().Add(-2 * time.Hour),
		RenewalRetries:   RENEWAL_RETRIES - 1,
		Token:            oidc.Token{AccessToken: fakeAccessToken(t, time.Now().Add(-time.Minute)), RefreshToken: "refresh"},
	}, "state-1")
	if err != nil {
		t.Fatalf("save error: %s", err)
	}

	r.renewAll()

	if len(disabled) != 1 || disabled[0] != user.ID {
		t.Fatalf("expected disable hook for %s, got %v", user.ID, disabled)
	}
	updated, err := r.userStore.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}
	if !updated.ConnectionsDisabledOnAuthFailure {
		t.Fatalf("expected ConnectionsDisabledOnAuthFailure to be set")
	}
	oauth2Data, _ := r.oidcStore.GetOAuth2DataByKey("state-1")
	if !oauth2Data.RenewalFailed {
		t.Fatalf("expected renewal to be marked as failed")
	}
}

// TestWorkerOnlyBacksOffAfterRenewal: entries that aren't renewed (pending
// logins without token) don't make the worker sleep.
func TestWorkerOnlyBacksOffAfterRenewal(t *testing.T) {
	sleeps := 0
	backoffSleep = func() { sleeps++ }
	r, _ := newTestRenewal(t, http.StatusBadRequest)
	for _, state := range []string{"a", "b", "c"} {
		if err := r.oidcStore.SaveOAuth2Data(oidc.OAuthData{ID: state, OIDCProviderID: "prov-1", CreatedAt: time.Now()}, state); err != nil {
			t.Fatalf("save error: %s", err)
		}
	}
	r.renewAll()
	if sleeps != 0 {
		t.Fatalf("expected no backoff for entries without renewal, got %d", sleeps)
	}
}

// TestWorkerSkipsRenewalWithoutRefreshToken: without a refresh token (e.g. the
// offline_access scope isn't requested) the token can't be renewed, and the
// user's connections must not be disabled for that.
func TestWorkerSkipsRenewalWithoutRefreshToken(t *testing.T) {
	backoffSleep = func() {}
	r, _ := newTestRenewal(t, http.StatusBadRequest)
	disabled := 0
	r.userStore.UserHooks.DisableFunc = func(_ storage.Iface, user users.User) error {
		disabled++
		return nil
	}
	if _, err := r.userStore.AddUser(users.User{Login: "john@example.com", OIDCID: "oidc-1"}); err != nil {
		t.Fatalf("add user error: %s", err)
	}
	err := r.oidcStore.SaveOAuth2Data(oidc.OAuthData{
		ID:               "oidc-1",
		OIDCProviderID:   "prov-1",
		CreatedAt:        time.Now().Add(-2 * time.Hour),
		LastTokenRenewal: time.Now().Add(-2 * time.Hour),
		Token:            oidc.Token{AccessToken: fakeAccessToken(t, time.Now().Add(-time.Minute))},
	}, "state-1")
	if err != nil {
		t.Fatalf("save error: %s", err)
	}
	for i := 0; i < RENEWAL_RETRIES+1; i++ {
		r.renewAll()
	}
	if disabled != 0 {
		t.Fatalf("connections were disabled for a user without refresh token")
	}
	oauth2Data, _ := r.oidcStore.GetOAuth2DataByKey("state-1")
	if oauth2Data.RenewalRetries != 0 || oauth2Data.RenewalFailed {
		t.Fatalf("renewal should not have been attempted: %+v", oauth2Data)
	}
}

// TestRenewalResetsRetriesOnSuccess: earlier failures don't count anymore after
// a successful renewal, so occasional failures over time don't disable a user.
func TestRenewalResetsRetriesOnSuccess(t *testing.T) {
	backoffSleep = func() {}
	newAccessToken := fakeAccessToken(t, time.Now().Add(time.Hour))
	r, _ := newTestRenewalWithTokenResponse(t, http.StatusOK, `{"access_token": "`+newAccessToken+`", "refresh_token": "refresh-2", "expires_in": 3600}`)
	if _, err := r.userStore.AddUser(users.User{Login: "john@example.com", OIDCID: "oidc-1"}); err != nil {
		t.Fatalf("add user error: %s", err)
	}
	err := r.oidcStore.SaveOAuth2Data(oidc.OAuthData{
		ID:               "oidc-1",
		OIDCProviderID:   "prov-1",
		CreatedAt:        time.Now().Add(-2 * time.Hour),
		LastTokenRenewal: time.Now().Add(-2 * time.Hour),
		RenewalRetries:   RENEWAL_RETRIES - 1,
		Token:            oidc.Token{AccessToken: fakeAccessToken(t, time.Now().Add(-time.Minute)), RefreshToken: "refresh"},
	}, "state-1")
	if err != nil {
		t.Fatalf("save error: %s", err)
	}
	r.renewAll()
	oauth2Data, _ := r.oidcStore.GetOAuth2DataByKey("state-1")
	if oauth2Data.Token.AccessToken != newAccessToken {
		t.Fatalf("token was not renewed: %+v", oauth2Data)
	}
	if oauth2Data.RenewalRetries != 0 {
		t.Fatalf("expected retries to be reset after a successful renewal, got %d", oauth2Data.RenewalRetries)
	}
}
