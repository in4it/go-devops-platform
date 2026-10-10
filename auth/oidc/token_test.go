package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestUpdateOAuth2DataWithTokenValidatesClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("can't generate key: %s", err)
	}
	jwks := Jwks{Keys: []JwksKey{{
		Kid: "kid-1",
		Alg: "RS256",
		Kty: "RSA",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		E:   "AQAB",
	}}}

	baseClaims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss":   "https://idp.inv",
			"aud":   "client-1",
			"sub":   "john",
			"email": "john@example.inv",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}
	}

	tests := []struct {
		name            string
		discoveryIssuer string
		modify          func(jwt.MapClaims)
		wantErr         bool
	}{
		{name: "valid", discoveryIssuer: "https://idp.inv", modify: func(jwt.MapClaims) {}},
		{name: "audience array", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { c["aud"] = []string{"other", "client-1"} }},
		{name: "wrong audience", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { c["aud"] = "other-client" }, wantErr: true},
		{name: "missing audience", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { delete(c, "aud") }, wantErr: true},
		{name: "wrong issuer", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { c["iss"] = "https://evil.inv" }, wantErr: true},
		{name: "email verified", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { c["email_verified"] = true }},
		{name: "email not verified", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { c["email_verified"] = false }, wantErr: true},
		{name: "email not verified (string)", discoveryIssuer: "https://idp.inv", modify: func(c jwt.MapClaims) { c["email_verified"] = "false" }, wantErr: true},
		{name: "tenant issuer", discoveryIssuer: "https://login.inv/{tenantid}/v2.0", modify: func(c jwt.MapClaims) {
			c["iss"] = "https://login.inv/tenant-1/v2.0"
			c["tid"] = "tenant-1"
		}},
		{name: "wrong tenant issuer", discoveryIssuer: "https://login.inv/{tenantid}/v2.0", modify: func(c jwt.MapClaims) {
			c["iss"] = "https://login.inv/tenant-2/v2.0"
			c["tid"] = "tenant-1"
		}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := baseClaims()
			tc.modify(claims)
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "kid-1"
			idToken, err := token.SignedString(privateKey)
			if err != nil {
				t.Fatalf("sign error: %s", err)
			}
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				out, _ := json.Marshal(Token{AccessToken: "access", IDToken: idToken})
				w.Write(out)
			}))
			defer ts.Close()
			discovery := Discovery{Issuer: tc.discoveryIssuer, TokenEndpoint: ts.URL + "/token"}
			oauthData, err := UpdateOAuth2DataWithToken(jwks, discovery, "client-1", "secret", "https://vpn.inv/callback", "code", "state", OAuthData{ID: "id-1"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if oauthData.UserInfo.Email != "john@example.inv" || oauthData.Subject != "john" {
				t.Fatalf("unexpected oauth data: %+v", oauthData)
			}
		})
	}
}
