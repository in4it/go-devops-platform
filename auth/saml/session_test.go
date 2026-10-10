package saml

import (
	"fmt"
	"sync"
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
)

// TestSessionsConcurrentAccess: run with -race. The SAML callback reads
// sessions while the ACS handler creates them.
func TestSessionsConcurrentAccess(t *testing.T) {
	s := &saml{
		sessions:        make(map[SessionKey]session),
		serviceProvider: make(map[string]*saml2.SAMLServiceProvider),
	}
	provider := Provider{ID: "prov-1"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			s.CreateSession(SessionKey{ProviderID: provider.ID, SessionID: fmt.Sprintf("s%d", i)}, AuthenticatedUser{Login: "john", ExpiresAt: time.Now().Add(time.Hour)})
		}(i)
		go func(i int) {
			defer wg.Done()
			_, _ = s.GetAuthenticatedUser(provider, fmt.Sprintf("s%d", i))
		}(i)
		go func() {
			defer wg.Done()
			_, _ = s.getServiceProvider(provider.ID)
		}()
	}
	wg.Wait()
	user, err := s.GetAuthenticatedUser(provider, "s1")
	if err != nil || user.Login != "john" {
		t.Fatalf("expected session s1, got %+v, %v", user, err)
	}
	if _, err := s.GetAuthenticatedUser(provider, "unknown"); err == nil {
		t.Fatalf("expected error for unknown session")
	}
}

func TestGetServiceProviderNil(t *testing.T) {
	s := &saml{serviceProvider: map[string]*saml2.SAMLServiceProvider{"prov-1": nil}}
	if _, ok := s.getServiceProvider("prov-1"); ok {
		t.Fatalf("nil service provider should not be returned as found")
	}
	if _, ok := s.getServiceProvider("missing"); ok {
		t.Fatalf("missing service provider should not be found")
	}
}
