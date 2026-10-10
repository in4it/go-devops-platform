package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/in4it/go-devops-platform/auth/oidc"
	"github.com/in4it/go-devops-platform/auth/provisioning/scim"
	"github.com/in4it/go-devops-platform/auth/saml"
	"github.com/in4it/go-devops-platform/rest/login"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

// newTestSAMLProvider creates a saml provider in the context, backed by a
// metadata test server
func newTestSAMLProvider(t *testing.T, c *Context) saml.Provider {
	t.Helper()
	c.Hostname = "example.inv"
	c.Protocol = "https"
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
	t.Cleanup(ts.Close)

	payload, _ := json.Marshal(saml.Provider{Name: "testProvider", MetadataURL: ts.URL + "/metadata"})
	req := httptest.NewRequest("POST", "http://example.com/api/saml-setup", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	c.samlSetupHandler(w, req)
	var samlProvider saml.Provider
	if err := json.NewDecoder(w.Result().Body).Decode(&samlProvider); err != nil || samlProvider.ID == "" {
		t.Fatalf("could not create saml provider: %v (status %d)", err, w.Result().StatusCode)
	}
	return samlProvider
}

func postSAMLCallback(c *Context, providerID, code string) (int, login.LoginResponse) {
	payload, _ := json.Marshal(SAMLCallback{Code: code, RedirectURI: "https://localhost.inv/something"})
	req := httptest.NewRequest("POST", "http://example.com/api/authmethods/saml/"+providerID, bytes.NewBuffer(payload))
	req.SetPathValue("method", "saml")
	req.SetPathValue("id", providerID)
	w := httptest.NewRecorder()
	c.authMethodsByID(w, req)
	var loginResponse login.LoginResponse
	_ = json.NewDecoder(w.Result().Body).Decode(&loginResponse)
	return w.Result().StatusCode, loginResponse
}

// TestSAMLCallbackCodeSingleUse: the code from the ACS handler can only be
// exchanged for a token once, and the token doesn't outlive local tokens.
func TestSAMLCallbackCodeSingleUse(t *testing.T) {
	c := newTestContext(t)
	samlProvider := newTestSAMLProvider(t, c)

	c.SAML.Client.CreateSession(saml.SessionKey{ProviderID: samlProvider.ID, SessionID: "abc"}, saml.AuthenticatedUser{ID: "123", Login: "john@example.com", ExpiresAt: time.Now().AddDate(0, 0, 30)})
	status, loginResponse := postSAMLCallback(c, samlProvider.ID, "abc")
	if status != http.StatusOK || !loginResponse.Authenticated || loginResponse.Token == "" {
		t.Fatalf("expected first callback to authenticate, got %d %+v", status, loginResponse)
	}
	token, err := jwt.Parse(loginResponse.Token, func(token *jwt.Token) (interface{}, error) {
		return c.JWTKeys.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("token parse error: %s", err)
	}
	exp, err := token.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		t.Fatalf("no expiration in token: %v", err)
	}
	if exp.After(time.Now().Add(login.MAX_TOKEN_LIFETIME + time.Minute)) {
		t.Fatalf("saml token lives longer than local tokens: %s", exp)
	}

	status, loginResponse = postSAMLCallback(c, samlProvider.ID, "abc")
	if status != http.StatusBadRequest || loginResponse.Token != "" {
		t.Fatalf("expected second callback with the same code to fail, got %d %+v", status, loginResponse)
	}
}

// TestExternalUserNotBlockedByLicense: new SSO users are created even when the
// user count is at the license limit (the license count can fall back to a low
// default when license detection fails at boot).
func TestExternalUserNotBlockedByLicense(t *testing.T) {
	storage := &memorystorage.MockMemoryStorage{}
	userStore, err := users.NewUserStore(storage, 100)
	if err != nil {
		t.Fatalf("userstore error: %s", err)
	}
	// license for 1 user
	c, err := newContextWithParams(storage, SERVER_TYPE_VPN, userStore, scim.New(storage, userStore, ""), 1, "", map[string]AppClient{})
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.SetupCompleted = true
	samlProvider := newTestSAMLProvider(t, c)
	if _, err := c.UserStore.AddUser(users.User{Login: "existing@example.com", SAMLID: "old"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	c.SAML.Client.CreateSession(saml.SessionKey{ProviderID: samlProvider.ID, SessionID: "new"}, saml.AuthenticatedUser{ID: "1", Login: "new@example.com", ExpiresAt: time.Now().Add(time.Hour)})
	status, loginResponse := postSAMLCallback(c, samlProvider.ID, "new")
	if status != http.StatusOK || !loginResponse.Authenticated || loginResponse.NoLicense {
		t.Fatalf("expected new user to log in, got %d %+v", status, loginResponse)
	}
	if !c.UserStore.LoginExists("new@example.com") {
		t.Fatalf("new user was not created")
	}
}

// TestExternalUserLinking: users can switch between saml and oidc logins, but an
// oidc login with an unverified email address can't take over a user that
// doesn't log in with oidc yet.
func TestExternalUserLinking(t *testing.T) {
	c := newTestContext(t)
	if _, err := c.UserStore.AddUser(users.User{Login: "saml@example.com", SAMLID: "saml-1"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	if _, err := c.UserStore.AddUser(users.User{Login: "oidc@example.com", OIDCID: "oidc-1"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	if _, err := c.UserStore.AddUser(users.User{Login: "local@example.com", Password: "localpass"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	unverified := externalUserOptions{EmailNotVerified: true}

	// unverified email: refused for users that don't log in with oidc yet
	for _, login := range []string{"saml@example.com", "local@example.com"} {
		if _, err := addOrModifyExternalUser(c.Storage.Client, c.UserStore, login, "oidc", "oidc-x", unverified); err == nil {
			t.Fatalf("expected oidc login with unverified email to be refused for %s", login)
		}
		user, _ := c.UserStore.GetUserByLogin(login)
		if user.OIDCID != "" {
			t.Fatalf("oidc id was linked for %s", login)
		}
	}
	// unverified email: allowed for an existing oidc user and for a new user
	if _, err := addOrModifyExternalUser(c.Storage.Client, c.UserStore, "oidc@example.com", "oidc", "oidc-2", unverified); err != nil {
		t.Fatalf("expected oidc login for existing oidc user: %s", err)
	}
	if _, err := addOrModifyExternalUser(c.Storage.Client, c.UserStore, "new@example.com", "oidc", "oidc-3", unverified); err != nil {
		t.Fatalf("expected new oidc user to be created: %s", err)
	}
	// switching between saml and oidc (verified email) works
	if _, err := addOrModifyExternalUser(c.Storage.Client, c.UserStore, "saml@example.com", "oidc", "oidc-4", externalUserOptions{}); err != nil {
		t.Fatalf("expected oidc login for saml user: %s", err)
	}
	if _, err := addOrModifyExternalUser(c.Storage.Client, c.UserStore, "oidc@example.com", "saml", "saml-2", externalUserOptions{}); err != nil {
		t.Fatalf("expected saml login for oidc user: %s", err)
	}
	samlUser, _ := c.UserStore.GetUserByLogin("saml@example.com")
	if samlUser.OIDCID != "oidc-4" {
		t.Fatalf("expected saml user to be linked to oidc, got %+v", samlUser)
	}
}

// TestOIDCCallbackStateSingleUse: a state that was already exchanged for a
// token can't be used to obtain the token again.
func TestOIDCCallbackStateSingleUse(t *testing.T) {
	c := newTestContext(t)
	c.OIDCProviders = []oidc.OIDCProvider{{ID: "prov-1", Name: "test", ClientID: "client", ClientSecret: "secret", DiscoveryURI: "http://127.0.0.1:1/discovery.json"}}
	if _, err := c.UserStore.AddUser(users.User{Login: "john@example.com", OIDCID: "oidc-1"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	err := c.OIDCStore.SaveOAuth2Data(oidc.OAuthData{ID: "oidc-1", OIDCProviderID: "prov-1", CreatedAt: time.Now(), Token: oidc.Token{AccessToken: "the-access-token"}}, "used-state")
	if err != nil {
		t.Fatalf("save error: %s", err)
	}
	payload, _ := json.Marshal(OIDCCallback{Code: "code", State: "used-state", RedirectURI: "/callback/oidc/prov-1"})
	req := httptest.NewRequest("POST", "http://example.com/api/authmethods/oidc/prov-1", bytes.NewBuffer(payload))
	req.SetPathValue("method", "oidc")
	req.SetPathValue("id", "prov-1")
	w := httptest.NewRecorder()
	c.authMethodsByID(w, req)
	body := w.Body.String()
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for reused state, got %d: %s", w.Result().StatusCode, body)
	}
	if strings.Contains(body, "the-access-token") {
		t.Fatalf("access token returned for reused state")
	}
}

// TestLoggingMiddlewareOmitsQuery: codes and states in query strings must not
// end up in the access log.
func TestLoggingMiddlewareOmitsQuery(t *testing.T) {
	c := newTestContext(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	handler := c.loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("GET", "http://example.com/callback/oidc/prov-1?code=secretcode&state=secretstate", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(buf.String(), "secretcode") || strings.Contains(buf.String(), "secretstate") {
		t.Fatalf("query string logged: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "req=/callback/oidc/prov-1 ") {
		t.Fatalf("path not logged: %s", buf.String())
	}
}

func userinfoType(t *testing.T, c *Context, user users.User) string {
	t.Helper()
	req := httptest.NewRequest("GET", "http://example.com/api/userinfo", nil)
	req = req.WithContext(context.WithValue(req.Context(), CustomValue("user"), user))
	w := httptest.NewRecorder()
	c.userinfoHandler(w, req)
	var response UserInfoResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&response); err != nil {
		t.Fatalf("decode error: %s", err)
	}
	return response.UserType
}

func TestUserinfoUserType(t *testing.T) {
	c := newTestContext(t)
	for expected, user := range map[string]users.User{
		"local": {Login: "local"},
		"oidc":  {Login: "oidc", OIDCID: "oidc-1"},
		"saml":  {Login: "saml", SAMLID: "saml-1"},
	} {
		if userType := userinfoType(t, c, user); userType != expected {
			t.Fatalf("expected userType %s, got %s", expected, userType)
		}
	}
}

func postProfilePassword(c *Context, user users.User, body string) int {
	req := httptest.NewRequest("POST", "http://example.com/api/profile/password", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), CustomValue("user"), user))
	w := httptest.NewRecorder()
	c.profilePasswordHandler(w, req)
	return w.Result().StatusCode
}

// TestProfilePasswordRequiresCurrentPassword: a local user needs the current
// password to set a new one; SSO users can't set a password.
func TestProfilePasswordRequiresCurrentPassword(t *testing.T) {
	c := newTestContext(t)
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	if status := postProfilePassword(c, user, `{"password": "newpass1!"}`); status != http.StatusBadRequest {
		t.Fatalf("expected 400 without current password, got %d", status)
	}
	if status := postProfilePassword(c, user, `{"password": "newpass1!", "currentPassword": "wrong"}`); status != http.StatusBadRequest {
		t.Fatalf("expected 400 with wrong current password, got %d", status)
	}
	if _, ok := c.UserStore.AuthUser("john", "mypass"); !ok {
		t.Fatalf("password changed without valid current password")
	}
	if status := postProfilePassword(c, user, `{"password": "newpass1!", "currentPassword": "mypass"}`); status != http.StatusOK {
		t.Fatalf("expected 200 with current password, got %d", status)
	}
	if _, ok := c.UserStore.AuthUser("john", "newpass1!"); !ok {
		t.Fatalf("password was not changed")
	}

	for _, ssoUser := range []users.User{
		{Login: "oidc@example.com", OIDCID: "oidc-1"},
		{Login: "saml@example.com", SAMLID: "saml-1"},
		{Login: "scim@example.com", Provisioned: true},
	} {
		added, err := c.UserStore.AddUser(ssoUser)
		if err != nil {
			t.Fatalf("cannot create user: %s", err)
		}
		if status := postProfilePassword(c, added, `{"password": "newpass1!", "currentPassword": ""}`); status != http.StatusForbidden {
			t.Fatalf("expected 403 for sso user %s, got %d", added.Login, status)
		}
	}
}

// TestReloadConfigReloadsUsers: users.json changed by another process (e.g. a
// password reset from the command line) is picked up on SIGHUP.
func TestReloadConfigReloadsUsers(t *testing.T) {
	c := newTestContext(t)
	hooks := &hookCalls{}
	hooks.install(c)
	user, err := c.UserStore.AddUser(users.User{Login: "admin", Password: "oldpass", Role: "admin"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}
	if err := SaveConfig(c); err != nil {
		t.Fatalf("save config error: %s", err)
	}
	// another process resets the password
	otherStore, err := users.NewUserStore(c.Storage.Client, 100)
	if err != nil {
		t.Fatalf("user store error: %s", err)
	}
	if err := otherStore.UpdatePassword(user.ID, "resetpass"); err != nil {
		t.Fatalf("update password error: %s", err)
	}
	userStore := c.UserStore

	c.ReloadConfig()

	if _, ok := c.UserStore.AuthUser("admin", "resetpass"); !ok {
		t.Fatalf("reset password not loaded after reload")
	}
	if userStore != c.UserStore {
		t.Fatalf("user store was replaced instead of reloaded")
	}
	if c.UserStore.UserHooks.DisableFunc == nil || c.UserStore.UserHooks.ReactivateFunc == nil {
		t.Fatalf("user hooks were lost on reload")
	}
	// the next save must not revert the reset
	if err := c.UserStore.SaveUsers(); err != nil {
		t.Fatalf("save users error: %s", err)
	}
	reread, _ := users.NewUserStore(c.Storage.Client, 100)
	if _, ok := reread.AuthUser("admin", "resetpass"); !ok {
		t.Fatalf("reset password reverted by save")
	}
}

// TestReloadConfigError: a failing reload must not crash the server.
func TestReloadConfigError(t *testing.T) {
	c := newTestContext(t)
	c.Hostname = "example.inv"
	if err := c.Storage.Client.WriteFile(c.Storage.Client.ConfigPath("config.json"), []byte("{invalid")); err != nil {
		t.Fatalf("write error: %s", err)
	}
	c.ReloadConfig()
	if c.Hostname != "example.inv" {
		t.Fatalf("config changed after failed reload")
	}
}

// TestOIDCProviderClientSecretNotReturned: the client secret is stored, but
// never returned to the browser.
func TestOIDCProviderClientSecretNotReturned(t *testing.T) {
	c := newTestContext(t)
	payload, _ := json.Marshal(oidc.OIDCProvider{Name: "test", ClientID: "client", ClientSecret: "supersecret", Scope: "openid", DiscoveryURI: "https://idp.inv/.well-known/openid-configuration"})
	req := httptest.NewRequest("POST", "http://example.com/api/oidc", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	c.oidcProviderHandler(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Result().StatusCode, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "supersecret") {
		t.Fatalf("client secret returned on create: %s", w.Body.String())
	}
	if len(c.OIDCProviders) != 1 || c.OIDCProviders[0].ClientSecret != "supersecret" {
		t.Fatalf("client secret not stored: %+v", c.OIDCProviders)
	}

	req = httptest.NewRequest("GET", "http://example.com/api/oidc", nil)
	w = httptest.NewRecorder()
	c.oidcProviderHandler(w, req)
	if strings.Contains(w.Body.String(), "supersecret") {
		t.Fatalf("client secret returned on list: %s", w.Body.String())
	}
	if c.OIDCProviders[0].ClientSecret != "supersecret" {
		t.Fatalf("listing removed the stored client secret")
	}
}
