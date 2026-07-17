package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	"github.com/in4it/go-devops-platform/users"
)

// requestWithClaims builds a request that already carries parsed JWT claims in
// its context, the way authMiddleware would leave them for GetUserFromRequest.
func requestWithClaims(c *Context, sub string, iat time.Time) *http.Request {
	claims := jwt.MapClaims{
		"iss": "wireguard-server",
		"sub": sub,
		"kid": c.JWTKeysKID,
		"iat": float64(iat.Unix()),
	}
	req := httptest.NewRequest("GET", "http://example.com/api/userinfo", nil)
	return req.WithContext(context.WithValue(req.Context(), CustomValue("claims"), claims))
}

// signedTokenWithIat signs a local JWT with an explicit issued-at so tests can
// deterministically place a token before or after a password change.
func signedTokenWithIat(t *testing.T, c *Context, login, role string, iat time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), jwt.MapClaims{
		"iss":  "wireguard-server",
		"sub":  login,
		"role": role,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  iat.Unix(),
	})
	token.Header["kid"] = c.JWTKeysKID
	tokenString, err := token.SignedString(c.JWTKeys.PrivateKey)
	if err != nil {
		t.Fatalf("could not sign token: %s", err)
	}
	return tokenString
}

func TestGetUserFromRequestNoPasswordChange(t *testing.T) {
	c, err := newContext(&memorystorage.MockMemoryStorage{}, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.UserStore.Empty()
	if _, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"}); err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	// user never changed their password: any iat is accepted
	req := requestWithClaims(c, "john", time.Now().Add(-72*time.Hour))
	if _, err := c.GetUserFromRequest(req); err != nil {
		t.Fatalf("expected token to be valid when password was never changed, got: %s", err)
	}
}

func TestGetUserFromRequestTokenBeforePasswordChange(t *testing.T) {
	c, err := newContext(&memorystorage.MockMemoryStorage{}, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.UserStore.Empty()
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	passwordChange := time.Now()
	if err := c.UserStore.UpdatePassword(user.ID, "newpass1!"); err != nil {
		t.Fatalf("update password error: %s", err)
	}

	// token issued an hour before the password change must be rejected
	req := requestWithClaims(c, "john", passwordChange.Add(-time.Hour))
	if _, err := c.GetUserFromRequest(req); err == nil {
		t.Fatalf("expected token issued before password change to be rejected")
	}
}

func TestGetUserFromRequestTokenAfterPasswordChange(t *testing.T) {
	c, err := newContext(&memorystorage.MockMemoryStorage{}, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.UserStore.Empty()
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	passwordChange := time.Now()
	if err := c.UserStore.UpdatePassword(user.ID, "newpass1!"); err != nil {
		t.Fatalf("update password error: %s", err)
	}

	// token issued after the password change (i.e. a fresh login) stays valid
	req := requestWithClaims(c, "john", passwordChange.Add(time.Hour))
	if _, err := c.GetUserFromRequest(req); err != nil {
		t.Fatalf("expected token issued after password change to be valid, got: %s", err)
	}
}

// TestAuthMiddlewareExpiresTokenIssuedBeforePasswordChange drives the full
// middleware chain (signature verification + user injection) to prove that an
// authenticated endpoint rejects a pre-password-change token but accepts a
// newer one.
func TestAuthMiddlewareExpiresTokenIssuedBeforePasswordChange(t *testing.T) {
	c, err := newContext(&memorystorage.MockMemoryStorage{}, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.SetupCompleted = true
	c.UserStore.Empty()
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	passwordChange := time.Now()
	if err := c.UserStore.UpdatePassword(user.ID, "newpass1!"); err != nil {
		t.Fatalf("update password error: %s", err)
	}

	handler := c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.userinfoHandler)))

	doRequest := func(token string) int {
		req := httptest.NewRequest("GET", "http://example.com/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	oldToken := signedTokenWithIat(t, c, "john", "user", passwordChange.Add(-time.Hour))
	if status := doRequest(oldToken); status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for token issued before password change, got %d", status)
	}

	newToken := signedTokenWithIat(t, c, "john", "user", passwordChange.Add(time.Hour))
	if status := doRequest(newToken); status != http.StatusOK {
		t.Fatalf("expected 200 for token issued after password change, got %d", status)
	}
}

// TestProfilePasswordHandlerStampsPasswordChangedAt verifies the self-service
// password change endpoint records the change time on the user.
func TestProfilePasswordHandlerStampsPasswordChangedAt(t *testing.T) {
	c, err := newContext(&memorystorage.MockMemoryStorage{}, SERVER_TYPE_VPN)
	if err != nil {
		t.Fatalf("cannot create context: %s", err)
	}
	c.UserStore.Empty()
	user, err := c.UserStore.AddUser(users.User{Login: "john", Password: "mypass"})
	if err != nil {
		t.Fatalf("cannot create user: %s", err)
	}

	payload, err := json.Marshal(users.User{Password: "newpass1!"})
	if err != nil {
		t.Fatalf("marshal error: %s", err)
	}
	req := httptest.NewRequest("POST", "http://example.com/api/profile/password", bytes.NewBuffer(payload))
	// the handler reads the authenticated user from context
	req = req.WithContext(context.WithValue(req.Context(), CustomValue("user"), user))
	w := httptest.NewRecorder()
	c.profilePasswordHandler(w, req)

	if status := w.Result().StatusCode; status != http.StatusOK {
		t.Fatalf("expected 200 from password handler, got %d", status)
	}

	updated, err := c.UserStore.GetUserByID(user.ID)
	if err != nil {
		t.Fatalf("get user error: %s", err)
	}
	if updated.PasswordChangedAt.IsZero() {
		t.Fatalf("expected PasswordChangedAt to be set after profile password change")
	}
}
