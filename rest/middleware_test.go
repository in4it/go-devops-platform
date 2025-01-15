package rest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsAdmin(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>Hello World!</body></html>")
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	IsAdminMiddleware(http.HandlerFunc(handler)).ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != 403 {
		t.Fatalf("expected permission denied")
	}
}

func TestInjectUserMiddlewareWithoutUser(t *testing.T) {
	c := Context{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(CustomValue("user"))
		if user != nil {
			t.Fatalf("user is not nil")
		}
		io.WriteString(w, "<html><body>Hello World!</body></html>")
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	c.injectUserMiddleware(http.HandlerFunc(handler)).ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200. Got: %d", resp.StatusCode)
	}
}
