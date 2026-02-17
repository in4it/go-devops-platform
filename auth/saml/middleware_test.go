package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	memorystorage "github.com/in4it/go-devops-platform/storage/memory"
	saml2 "github.com/russellhaering/gosaml2"
)

func TestLoadSP(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certB64 := base64.StdEncoding.EncodeToString(der)

	// Serve metadata via an HTTP test server.
	metadataXML := `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="urn:test:idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>` + certB64 + `</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>

    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example.com/sso" />
  </IDPSSODescriptor>
</EntityDescriptor>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// optional: validate your loader is requesting what you expect
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(metadataXML))
	}))
	t.Cleanup(ts.Close)

	localhost := "localhost"
	protocol := "http"
	s := &saml{
		storage:         &memorystorage.MockMemoryStorage{},
		hostname:        &localhost,
		protocol:        &protocol,
		serviceProvider: make(map[string]*saml2.SAMLServiceProvider),
	}

	provider := Provider{
		ID:                     "prov-1",
		Name:                   "Test Provider",
		MetadataURL:            ts.URL,
		AllowMissingAttributes: true,
	}

	if err := s.loadSP(provider); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if s.serviceProvider[provider.ID] == nil {
		t.Fatalf("expected serviceProvider[%q] to be set", provider.ID)
	}
	serviceProvider := s.serviceProvider[provider.ID]
	if serviceProvider.IdentityProviderSSOURL != "https://idp.example.com/sso" {
		t.Errorf("unexpected IdentityProviderSSOURL: %s", serviceProvider.IdentityProviderSSOURL)
	}
	roots, err := serviceProvider.IDPCertificateStore.Certificates()
	if err != nil {
		t.Fatalf("IDPCertificateStore.Certificates error: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("expected 1 cert in IDPCertificateStore, got %d", len(roots))
	}
	cert := roots[0]
	if cert.SerialNumber.Cmp(tpl.SerialNumber) != 0 {
		t.Errorf("unexpected cert SerialNumber: got %s, want %s", cert.SerialNumber, tpl.SerialNumber)
	}
	if cert.IsCA != tpl.IsCA {
		t.Errorf("unexpected cert IsCA: got %t, want %t", cert.IsCA, tpl.IsCA)
	}
}
