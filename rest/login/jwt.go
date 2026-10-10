package login

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MAX_TOKEN_LIFETIME is the lifetime of local tokens, and the maximum lifetime
// of tokens issued for external (SAML) logins
const MAX_TOKEN_LIFETIME = 72 * time.Hour

func GetJWTToken(login, role string, signKey *rsa.PrivateKey, kid string) (string, error) {
	return GetJWTTokenWithExpiration(login, role, signKey, kid, time.Now().Add(MAX_TOKEN_LIFETIME))
}

func GetJWTTokenWithExpiration(login, role string, signKey *rsa.PrivateKey, kid string, expiration time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), jwt.MapClaims{
		"iss":  "wireguard-server",
		"sub":  login,
		"role": role,
		"exp":  expiration.Unix(),
		"iat":  time.Now().Unix(),
	})
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(signKey)

	return tokenString, err
}
