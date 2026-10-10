package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/in4it/go-devops-platform/auth/oidc"
	"github.com/in4it/go-devops-platform/auth/saml"
	"github.com/in4it/go-devops-platform/rest/login"
	"github.com/in4it/go-devops-platform/storage"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

// requestWithOIDCClaims builds a request carrying claims of a token issued by an
// oidc provider (kid is not the local jwt key id)
func requestWithOIDCClaims(c *Context, iss, sub string) *http.Request {
	claims := jwt.MapClaims{
		"iss": iss,
		"sub": sub,
		"kid": "oidc-provider-kid",
	}
	req := httptest.NewRequest("GET", "http://example.com/api/userinfo", nil)
	return req.WithContext(context.WithValue(req.Context(), CustomValue("claims"), claims))
}

func newTestContext(t *testing.T) *Context {
	t.Helper()
	c, err := newContext(&memorystorage.MockMemoryStorage{}, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.SetupCompleted = true
	c.UserStore.Empty()
	return c
}

func TestGetUserFromRequestSuspendedUser(t *testing.T) {
	c := newTestContext(t)
	if _, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass", Suspended: true}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	req := requestWithClaims(c, "john", time.Now())
	if _, err := c.GetUserFromRequest(req); err == nil {
		t.Fatalf("expected error for suspended user")
	}
}

func TestGetUserFromRequestSuspendedOIDCUser(t *testing.T) {
	c := newTestContext(t)
	if err := c.OIDCStore.SaveOAuth2Data(oidc.OAuthData{ID: "oidc-1", Issuer: "https://idp.inv", Subject: "sub-1"}, "state-1"); err != nil {
		t.Fatalf("save oauth2 data error: %s", err)
	}
	if _, err := c.UserStore.AddUser(users.User{Login: "john@example.com", OIDCID: "oidc-1", Suspended: true}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	req := requestWithOIDCClaims(c, "https://idp.inv", "sub-1")
	if _, err := c.GetUserFromRequest(req); err == nil {
		t.Fatalf("expected error for suspended oidc user")
	}
}

// TestSuspendedUserTokenRejected makes sure a token issued before a user got
// suspended can't be used anymore on authenticated endpoints.
func TestSuspendedUserTokenRejected(t *testing.T) {
	c := newTestContext(t)
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	token := signedTokenWithIat(t, c, "john", "user", time.Now())
	handler := c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.userinfoHandler)))
	doRequest := func() int {
		req := httptest.NewRequest("GET", "http://example.com/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result().StatusCode
	}
	if status := doRequest(); status != http.StatusOK {
		t.Fatalf("expected 200 before suspension, got %d", status)
	}
	user.Suspended = true
	if err := c.UserStore.UpdateUser(user); err != nil {
		t.Fatalf("update user error: %s", err)
	}
	if status := doRequest(); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 after suspension, got %d", status)
	}
}

func TestUpgradeEndpointRequiresAdmin(t *testing.T) {
	c := newTestContext(t)
	if _, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass", Role: "user"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	mux := c.getRouter(fstest.MapFS{}, []byte("<html></html>"))

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "http://example.com/api/upgrade", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if status := w.Result().StatusCode; status != http.StatusUnauthorized {
			t.Fatalf("%s without token: expected 401, got %d", method, status)
		}

		req = httptest.NewRequest(method, "http://example.com/api/upgrade", nil)
		req.Header.Set("Authorization", "Bearer "+signedTokenWithIat(t, c, "john", "user", time.Now()))
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if status := w.Result().StatusCode; status != http.StatusForbidden {
			t.Fatalf("%s with user token: expected 403, got %d", method, status)
		}
	}
}

type hookCalls struct {
	mu          sync.Mutex
	disabled    []string
	reactivated []string
}

func (h *hookCalls) install(c *Context) {
	c.UserStore.UserHooks.DisableFunc = func(_ storage.Iface, user users.User) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.disabled = append(h.disabled, user.ID)
		return nil
	}
	c.UserStore.UserHooks.ReactivateFunc = func(_ storage.Iface, user users.User) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.reactivated = append(h.reactivated, user.ID)
		return nil
	}
}

func patchUser(c *Context, id string, body string) int {
	req := httptest.NewRequest("PATCH", "http://example.com/api/user/"+id, bytes.NewBufferString(body))
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	c.userHandler(w, req)
	return w.Result().StatusCode
}

// TestUserPatchPasswordKeepsSuspended: the admin "change password" action only
// sends the id and password. That must not unsuspend the user.
func TestUserPatchPasswordKeepsSuspended(t *testing.T) {
	c := newTestContext(t)
	hooks := &hookCalls{}
	hooks.install(c)
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass", Suspended: true})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	if status := patchUser(c, user.ID, fmt.Sprintf(`{"id": %q, "password": "newpass1!"}`, user.ID)); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	updated, err := c.UserStore.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}
	if !updated.Suspended {
		t.Fatalf("password change unsuspended the user")
	}
	if len(hooks.reactivated) != 0 {
		t.Fatalf("password change reactivated the user's connections: %v", hooks.reactivated)
	}
	if _, ok := c.UserStore.AuthUser("john", "newpass1!"); !ok {
		t.Fatalf("password was not changed")
	}
}

// TestUserPatchUsesPathID: the id in the body must not select which user's
// hooks run or which password is changed.
func TestUserPatchUsesPathID(t *testing.T) {
	c := newTestContext(t)
	hooks := &hookCalls{}
	hooks.install(c)
	john, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	jane, err := c.UserStore.AddUser(users.User{Login: "jane", Password: "janepass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	body := fmt.Sprintf(`{"id": %q, "suspended": true, "password": "newpass1!"}`, jane.ID)
	if status := patchUser(c, john.ID, body); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(hooks.disabled) != 1 || hooks.disabled[0] != john.ID {
		t.Fatalf("expected disable hook for john (%s), got %v", john.ID, hooks.disabled)
	}
	if _, ok := c.UserStore.AuthUser("jane", "janepass"); !ok {
		t.Fatalf("jane's password was changed through john's endpoint")
	}
	if _, ok := c.UserStore.AuthUser("john", "newpass1!"); !ok {
		t.Fatalf("john's password was not changed")
	}

	// unsuspend
	if status := patchUser(c, john.ID, `{"suspended": false}`); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(hooks.reactivated) != 1 || hooks.reactivated[0] != john.ID {
		t.Fatalf("expected reactivate hook for john, got %v", hooks.reactivated)
	}
	updated, _ := c.UserStore.GetUserByID(john.ID)
	if updated.Suspended {
		t.Fatalf("expected john to be unsuspended")
	}
}

func TestUserPatchInvalidRole(t *testing.T) {
	c := newTestContext(t)
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass", Role: "user"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	if status := patchUser(c, user.ID, `{"role": "superadmin"}`); status != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid role, got %d", status)
	}
	updated, _ := c.UserStore.GetUserByID(user.ID)
	if updated.Role != "user" {
		t.Fatalf("role changed to %q", updated.Role)
	}
	if status := patchUser(c, user.ID, `{"role": "admin"}`); status != http.StatusOK {
		t.Fatalf("expected 200 for valid role, got %d", status)
	}
}

func postLogin(c *Context, loginName, password string) int {
	payload, _ := json.Marshal(login.LoginRequest{Login: loginName, Password: password})
	req := httptest.NewRequest("POST", "http://example.com/api/auth", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	c.authHandler(w, req)
	return w.Result().StatusCode
}

// TestLoginRateLimitParallel sends parallel failed logins. Before the fix this
// crashed the process (concurrent map read and write) and let every request
// through the limit. Run with -race.
func TestLoginRateLimitParallel(t *testing.T) {
	c := newTestContext(t)
	if _, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[int]int{}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status := postLogin(c, "john", "wrong")
			// also hit other logins, to exercise map writes for different keys
			postLogin(c, fmt.Sprintf("user%d", i), "wrong")
			mu.Lock()
			statuses[status]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if statuses[http.StatusUnauthorized] != login.MAX_LOGIN_ATTEMPTS {
		t.Fatalf("expected exactly %d password checks, got statuses %v", login.MAX_LOGIN_ATTEMPTS, statuses)
	}
	if statuses[http.StatusTooManyRequests] != 30-login.MAX_LOGIN_ATTEMPTS {
		t.Fatalf("expected the rest to be rate limited, got statuses %v", statuses)
	}
	// the correct password is rate limited too while locked out
	if status := postLogin(c, "john", "mypass"); status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while locked out, got %d", status)
	}
}

func TestLoginSuccessClearsAttempts(t *testing.T) {
	c := newTestContext(t)
	if _, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	for i := 0; i < login.MAX_LOGIN_ATTEMPTS-1; i++ {
		if status := postLogin(c, "john", "wrong"); status != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", status)
		}
	}
	if status := postLogin(c, "john", "mypass"); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	for i := 0; i < login.MAX_LOGIN_ATTEMPTS; i++ {
		if status := postLogin(c, "john", "wrong"); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d after successful login: expected 401, got %d", i, status)
		}
	}
	if status := postLogin(c, "john", "wrong"); status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", status)
	}
}

// TestOIDCStoreConcurrentAccess exercises the request paths that read the oidc
// store while unauthenticated requests write to it. Run with -race.
func TestOIDCStoreConcurrentAccess(t *testing.T) {
	c := newTestContext(t)
	handler := c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.userinfoHandler)))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = c.OIDCStore.SaveOAuth2Data(oidc.OAuthData{ID: fmt.Sprintf("id-%d", i), CreatedAt: time.Now()}, fmt.Sprintf("state-%d", i))
		}(i)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://example.com/api/userinfo", nil)
			req.Header.Set("Authorization", "Bearer x.y.z")
			handler.ServeHTTP(httptest.NewRecorder(), req)
			_, _ = c.GetUserFromRequest(requestWithOIDCClaims(c, "iss", "sub"))
		}()
	}
	wg.Wait()
	if len(c.OIDCStore.GetOAuth2DataCopy()) != 20 {
		t.Fatalf("expected 20 entries, got %d", len(c.OIDCStore.GetOAuth2DataCopy()))
	}
}

// TestSAMLCallbackSuspendedUser: a suspended user completing a SAML login must
// not get a token, and must not get their connections reactivated.
func TestSAMLCallbackSuspendedUser(t *testing.T) {
	c := newTestContext(t)
	c.Hostname = "example.inv"
	c.Protocol = "https"
	hooks := &hookCalls{}
	hooks.install(c)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "/metadata" {
			out, err := xml.Marshal(getSAMLCert("http://localhost.inv"))
			if err != nil {
				t.Errorf("marshal error: %s", err)
			}
			w.Write(out)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	payload, _ := json.Marshal(saml.Provider{Name: "testProvider", MetadataURL: ts.URL + "/metadata"})
	req := httptest.NewRequest("POST", "http://example.com/api/saml-setup", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	c.samlSetupHandler(w, req)
	var samlProvider saml.Provider
	if err := json.NewDecoder(w.Result().Body).Decode(&samlProvider); err != nil || samlProvider.ID == "" {
		t.Fatalf("could not create saml provider: %v (status %d)", err, w.Result().StatusCode)
	}

	if _, err := c.UserStore.AddUser(users.User{Login: "john@example.com", Suspended: true, ConnectionsDisabledOnAuthFailure: true}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	c.SAML.Client.CreateSession(saml.SessionKey{ProviderID: samlProvider.ID, SessionID: "abc"}, saml.AuthenticatedUser{ID: "123", Login: "john@example.com", ExpiresAt: time.Now().AddDate(0, 0, 1)})
	payload, _ = json.Marshal(SAMLCallback{Code: "abc", RedirectURI: "https://localhost.inv/something"})
	req = httptest.NewRequest("POST", "http://example.com/api/authmethods/saml/"+samlProvider.ID, bytes.NewBuffer(payload))
	req.SetPathValue("method", "saml")
	req.SetPathValue("id", samlProvider.ID)
	w = httptest.NewRecorder()
	c.authMethodsByID(w, req)
	if status := w.Result().StatusCode; status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	var loginResponse login.LoginResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&loginResponse); err != nil {
		t.Fatalf("decode error: %s", err)
	}
	if !loginResponse.Suspended {
		t.Fatalf("expected suspended in login response")
	}
	if loginResponse.Authenticated || loginResponse.Token != "" {
		t.Fatalf("suspended user got a token")
	}
	if len(hooks.reactivated) != 0 {
		t.Fatalf("suspended user's connections were reactivated")
	}
}

// TestExternalLoginReactivatesConnections: connections disabled because SSO
// token renewal failed are enabled again on the next successful SSO login,
// unless the user is suspended.
func TestExternalLoginReactivatesConnections(t *testing.T) {
	for _, suspended := range []bool{false, true} {
		t.Run(fmt.Sprintf("suspended=%v", suspended), func(t *testing.T) {
			c := newTestContext(t)
			hooks := &hookCalls{}
			hooks.install(c)
			user, err := c.UserStore.AddUser(users.User{Login: "john@example.com", ConnectionsDisabledOnAuthFailure: true, Suspended: suspended})
			if err != nil {
				t.Fatalf("cannot create user: %s", err)
			}
			if _, err := addOrModifyExternalUser(c.Storage.Client, c.UserStore, c.LicenseUserCount, "john@example.com", "oidc", "oidc-1"); err != nil {
				t.Fatalf("addOrModifyExternalUser error: %s", err)
			}
			updated, err := c.UserStore.GetUserByID(user.ID)
			if err != nil {
				t.Fatalf("get user error: %s", err)
			}
			if suspended {
				if len(hooks.reactivated) != 0 {
					t.Fatalf("suspended user's connections were reactivated")
				}
				if !updated.ConnectionsDisabledOnAuthFailure {
					t.Fatalf("flag should stay set while suspended, so connections come back after unsuspend + login")
				}
			} else {
				if len(hooks.reactivated) != 1 || hooks.reactivated[0] != user.ID {
					t.Fatalf("expected connections to be reactivated, got %v", hooks.reactivated)
				}
				if updated.ConnectionsDisabledOnAuthFailure {
					t.Fatalf("expected ConnectionsDisabledOnAuthFailure to be cleared")
				}
			}
		})
	}
}
