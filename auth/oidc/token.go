package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/in4it/go-devops-platform/logging"
)

func RetrieveOAUth2DataUsingState(allOAuth2data map[string]OAuthData, state string) (OAuthData, error) {
	if state == "" {
		return OAuthData{}, fmt.Errorf("no state found")
	}
	oauthData, ok := allOAuth2data[state]
	if !ok {
		return OAuthData{}, fmt.Errorf("oauth data not found (is state missing?)")
	}
	return oauthData, nil
}

func UpdateOAuth2DataWithToken(jwks Jwks, discovery Discovery, clientID, clientSecret, redirectURI, code, state string, oauth2Data OAuthData) (OAuthData, error) {
	newOAuthData := oauth2Data
	var token Token
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	if discovery.TokenEndpoint == "" {
		return newOAuthData, fmt.Errorf("token endpoint is empty")
	}

	payload := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
	}

	resp, err := client.PostForm(discovery.TokenEndpoint, payload)
	if err != nil {
		return newOAuthData, fmt.Errorf("tokenEndpoint PostForm error: %s", err)
	}
	renewalTime := time.Now()
	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return newOAuthData, fmt.Errorf("tokenEndpoint return error. statuscode: %d", resp.StatusCode)
		}
		return newOAuthData, fmt.Errorf("tokenEndpoint return error (statuscode %d): %s", resp.StatusCode, data)
	}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&token)
	if err != nil {
		return newOAuthData, fmt.Errorf("tokenEndpoint decode error: %s", err)
	}

	// verify id token
	parsedToken, err := jwt.Parse(token.IDToken, func(token *jwt.Token) (interface{}, error) {
		publicKey, err := GetPublicKeyForToken([]Jwks{jwks}, []Discovery{discovery}, token)
		if err != nil {
			return nil, fmt.Errorf("GetPublicKeyForToken error: %s", err)
		}
		return publicKey, nil
	})
	if err != nil {
		logging.DebugLog(fmt.Errorf("couldn't verify id token: %s", err))
		return newOAuthData, fmt.Errorf("couldn't verify id token")
	}
	// remove old oauth2data matching oidcproivder and subject
	claims := parsedToken.Claims.(jwt.MapClaims)
	subject, ok := claims["sub"]
	if !ok {
		return newOAuthData, fmt.Errorf("subject missing from id token")
	}
	validEmail := ""
	email, ok := claims["email"]
	if !ok {
		// check if email is in preferred_username
		preferred_username, ok2 := claims["preferred_username"]
		if !ok2 {
			return newOAuthData, fmt.Errorf("email missing from id token (not in email / preferred_username claim)")
		} else {
			_, err := mail.ParseAddress(preferred_username.(string))
			if err != nil {
				return newOAuthData, fmt.Errorf("email missing from id token and preferred_username is not an email address")
			}
			validEmail = preferred_username.(string)
		}
	} else {
		validEmail = email.(string)
	}
	issuer, ok := claims["iss"]
	if !ok {
		return newOAuthData, fmt.Errorf("issuer missing from id token")
	}
	err = validateIDTokenClaims(claims, discovery, clientID)
	if err != nil {
		return newOAuthData, err
	}

	newOAuthData.Token = token
	newOAuthData.LastTokenRenewal = renewalTime
	newOAuthData.Subject = subject.(string)
	newOAuthData.Issuer = issuer.(string)
	newOAuthData.UserInfo.Email = validEmail
	newOAuthData.UserInfo.EmailNotVerified = emailNotVerified(claims)
	return newOAuthData, nil
}

func GetPublicKeyForToken(allJwks []Jwks, discoveryProviders []Discovery, token *jwt.Token) (any, error) {
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("no kid found in token")
	}
	for _, jwks := range allJwks {
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				jsonWebKey := jose.JSONWebKey{}
				singleKey, err := json.Marshal(key)
				if err != nil {
					return nil, fmt.Errorf("internal server error: cannot marshal key from kid endpoint: %s", err)
				}
				err = jsonWebKey.UnmarshalJSON(singleKey)
				if err != nil {
					return nil, fmt.Errorf("key from jwks import error: %s", err)
				}
				return jsonWebKey.Key, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching kid found for token")
}

// validateIDTokenClaims checks the audience and issuer claims of an id token
func validateIDTokenClaims(claims jwt.MapClaims, discovery Discovery, clientID string) error {
	audience, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("invalid audience in id token: %s", err)
	}
	if !slices.Contains(audience, clientID) {
		return fmt.Errorf("id token audience doesn't contain the client id")
	}
	issuer, ok := claims["iss"].(string)
	if !ok {
		return fmt.Errorf("issuer in id token is not a string")
	}
	if discovery.Issuer != "" {
		expectedIssuer := discovery.Issuer
		// multi-tenant discovery documents (e.g. Microsoft Entra ID's common endpoint) use a {tenantid} placeholder
		if strings.Contains(expectedIssuer, "{tenantid}") {
			if tenantID, ok := claims["tid"].(string); ok && tenantID != "" {
				expectedIssuer = strings.ReplaceAll(expectedIssuer, "{tenantid}", tenantID)
			}
		}
		if !issuerMatches(issuer, expectedIssuer) {
			return fmt.Errorf("id token issuer doesn't match the issuer of the oidc provider")
		}
	}
	return nil
}

// issuerMatches compares the id token issuer with the issuer of the discovery
// document. Google documents both https://accounts.google.com and
// accounts.google.com as valid issuers.
func issuerMatches(issuer, expectedIssuer string) bool {
	if issuer == expectedIssuer {
		return true
	}
	if expectedIssuer == "https://accounts.google.com" && issuer == "accounts.google.com" {
		return true
	}
	return false
}

// emailNotVerified returns true when the IdP explicitly says the email address
// is not verified (email_verified=false). A missing claim is not treated as unverified.
func emailNotVerified(claims jwt.MapClaims) bool {
	emailVerified, ok := claims["email_verified"]
	if !ok {
		return false
	}
	switch v := emailVerified.(type) {
	case bool:
		return !v
	case string:
		return strings.EqualFold(v, "false")
	}
	return false
}
