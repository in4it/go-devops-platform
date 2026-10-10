package scim

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

func (s *Scim) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			writeWithStatus(w, []byte(`{"error": "token not found"}`), http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(tokenString) == 0 {
			returnError(w, fmt.Errorf("empty token"), http.StatusUnauthorized)
			return
		}
		if s.Token == "" {
			writeWithStatus(w, []byte(`{"error": "scim not active"}`), http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(s.Token), []byte(tokenString)) != 1 {
			writeWithStatus(w, []byte(`{"error": "authentication failed"}`), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
