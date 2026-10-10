package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	tests := []struct {
		configuredToken string
		header          string
		expectedStatus  int
	}{
		{configuredToken: "token", header: "Bearer token", expectedStatus: http.StatusOK},
		{configuredToken: "token", header: "Bearer wrong", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "token", header: "Bearer tok", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "token", header: "Bearer tokenx", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "token", header: "Bearer Bearer token", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "token", header: "Bearer ", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "token", header: "token", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "", header: "Bearer ", expectedStatus: http.StatusUnauthorized},
		{configuredToken: "", header: "Bearer x", expectedStatus: http.StatusUnauthorized},
	}
	for _, test := range tests {
		s := &Scim{Token: test.configuredToken}
		handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest("GET", "http://example.com/api/scim/v2/Users", nil)
		req.Header.Set("Authorization", test.header)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != test.expectedStatus {
			t.Fatalf("token %q, header %q: expected status %d, got %d", test.configuredToken, test.header, test.expectedStatus, w.Code)
		}
	}
}
