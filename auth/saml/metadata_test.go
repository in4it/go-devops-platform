package saml

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const minimalSAMLMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="urn:test:idp">
</EntityDescriptor>`

func TestHasValidMetadata(t *testing.T) {
	s := &saml{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if got := r.Header.Get("Accept"); got == "" {
			t.Fatalf("expected Accept header to be set")
		}

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		fmt.Fprint(w, minimalSAMLMetadata)
	}))
	defer ts.Close()

	hasValidMetadata, err := s.HasValidMetadataURL(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasValidMetadata {
		t.Fatalf("expected metadata to be valid")
	}
}

func TestHasValidMetadata_InvalidURL(t *testing.T) {
	s := &saml{}

	hasValidMetadata, err := s.HasValidMetadataURL("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err == nil {
		t.Fatalf("expected error for blocked cloud metadata URL, got nil")
	}
	if hasValidMetadata {
		t.Fatalf("expected metadata to be invalid for blocked cloud metadata URL")
	}
}
func TestGetMetadata(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if got := r.Header.Get("Accept"); got == "" {
			t.Fatalf("expected Accept header to be set")
		}

		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		fmt.Fprint(w, minimalSAMLMetadata)
	}))
	defer ts.Close()

	metadata, err := getMetadata(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metadata.EntityID != "urn:test:idp" {
		t.Fatalf("expected EntityID to be 'urn:test:idp', got %q", metadata.EntityID)
	}
}
