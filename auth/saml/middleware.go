package saml

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

const ISSUER_URL = "saml/iss"
const AUDIENCE_URL = "saml/aud"
const ACS_URL = "saml/acs"

func (s *saml) ensureSPLoaded(provider Provider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, ok := s.serviceProvider[provider.ID]
	if !ok {
		err := s.loadSP(provider)
		if err != nil {
			return fmt.Errorf("could not load saml provider: %s", err)
		}
		return nil
	}
	// check if provider is up-to-date
	if sp == nil || provider.AllowMissingAttributes != sp.AllowMissingAttributes {
		err := s.loadSP(provider)
		if err != nil {
			return fmt.Errorf("could not reload saml provider: %s", err)
		}
	}
	return nil
}

// getServiceProvider returns the loaded service provider for a provider id
func (s *saml) getServiceProvider(providerID string) (*saml2.SAMLServiceProvider, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, ok := s.serviceProvider[providerID]
	return sp, ok && sp != nil
}

// loadSP loads the service provider. Must be called with s.mu held.
func (s *saml) loadSP(provider Provider) error {
	idpMetadataURL, err := url.Parse(provider.MetadataURL)
	if err != nil {
		return fmt.Errorf("can't parse metadata url: %s", err)
	}
	// pull metadata
	metadata, err := getMetadata(idpMetadataURL)
	if err != nil {
		return fmt.Errorf("can't decode saml cert data: %s", err)
	}

	// load certs
	certStore := dsig.MemoryX509CertificateStore{}

	if metadata.IDPSSODescriptor == nil || len(metadata.IDPSSODescriptor.KeyDescriptors) == 0 {
		return fmt.Errorf("keyDescriptors are empty")
	}
	if len(metadata.IDPSSODescriptor.SingleSignOnServices) == 0 {
		return fmt.Errorf("SingleSignOnServices not found")
	}

	certStore.Roots, err = getSAMLCertsFromMetadata(metadata.IDPSSODescriptor.KeyDescriptors)
	if err != nil {
		return fmt.Errorf("can't parse certs from metadata: %s", err)
	}

	keyStore := NewKeyPair(s.storage, *s.hostname)

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       fmt.Sprintf("%s://%s/%s/%s", *s.protocol, *s.hostname, ISSUER_URL, provider.ID),
		AssertionConsumerServiceURL: fmt.Sprintf("%s://%s/%s/%s", *s.protocol, *s.hostname, ACS_URL, provider.ID),
		SignAuthnRequests:           true,
		AudienceURI:                 fmt.Sprintf("%s://%s/%s/%s", *s.protocol, *s.hostname, AUDIENCE_URL, provider.ID),
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  keyStore,
		AllowMissingAttributes:      provider.AllowMissingAttributes,
	}

	s.serviceProvider[provider.ID] = sp

	return err
}

func getSAMLCertsFromMetadata(keyDescriptors []types.KeyDescriptor) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	for _, kd := range keyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return nil, fmt.Errorf("metadata certificate(%d) must not be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return nil, fmt.Errorf("decode error:%s", err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, fmt.Errorf("cert parse error: %s", err)
			}

			certs = append(certs, idpCert)
		}
	}

	return certs, nil

}

func (s *saml) GetAuthURL(provider Provider) (string, error) {
	err := s.ensureSPLoaded(provider)
	if err != nil {
		return "", fmt.Errorf("saml error: invalid saml configuration: %s", err)
	}
	sp, ok := s.getServiceProvider(provider.ID)
	if !ok {
		return "", fmt.Errorf("provider not found")
	}
	return sp.BuildAuthURL("")
}
