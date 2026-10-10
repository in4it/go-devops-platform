package saml

import (
	"testing"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
)

func newTestSAML() *saml {
	return New(&[]Provider{}, nil, nil, nil).(*saml)
}

func testAssertionInfo(id string, notOnOrAfter string, sessionNotOnOrAfter *time.Time) *saml2.AssertionInfo {
	return &saml2.AssertionInfo{
		NameID:              "john@example.com",
		SessionNotOnOrAfter: sessionNotOnOrAfter,
		Assertions: []types.Assertion{
			{ID: id, Conditions: &types.Conditions{NotOnOrAfter: notOnOrAfter}},
		},
	}
}

// TestSAMLSessionSingleUse: the code handed out by the ACS handler can only be
// redeemed once.
func TestSAMLSessionSingleUse(t *testing.T) {
	s := newTestSAML()
	provider := Provider{ID: "prov-1"}
	s.CreateSession(SessionKey{ProviderID: provider.ID, SessionID: "code-1"}, AuthenticatedUser{Login: "john", ExpiresAt: time.Now().Add(time.Hour)})

	user, err := s.ConsumeAuthenticatedUser(provider, "code-1")
	if err != nil || user.Login != "john" {
		t.Fatalf("expected first redeem to succeed, got %+v, %v", user, err)
	}
	if _, err := s.ConsumeAuthenticatedUser(provider, "code-1"); err == nil {
		t.Fatalf("expected second redeem of the same code to fail")
	}
	if _, err := s.GetAuthenticatedUser(provider, "code-1"); err == nil {
		t.Fatalf("expected consumed session to be gone")
	}
}

// TestSAMLSessionRedeemTTL: a code can only be redeemed shortly after it was
// created, even if the user's SAML session is valid for longer. Expired
// sessions are pruned when a new session is created.
func TestSAMLSessionRedeemTTL(t *testing.T) {
	s := newTestSAML()
	provider := Provider{ID: "prov-1"}
	oldKey := SessionKey{ProviderID: provider.ID, SessionID: "old"}
	s.sessions[oldKey] = session{
		user:      AuthenticatedUser{Login: "john", ExpiresAt: time.Now().Add(24 * time.Hour)},
		createdAt: time.Now().Add(-SESSION_REDEEM_TTL - time.Second),
	}
	if _, err := s.GetAuthenticatedUser(provider, "old"); err == nil {
		t.Fatalf("expected session older than the redeem ttl to be expired")
	}
	s.CreateSession(SessionKey{ProviderID: provider.ID, SessionID: "new"}, AuthenticatedUser{Login: "jane", ExpiresAt: time.Now().Add(time.Hour)})
	if _, ok := s.sessions[oldKey]; ok {
		t.Fatalf("expected expired session to be pruned on create")
	}
	if _, err := s.ConsumeAuthenticatedUser(provider, "new"); err != nil {
		t.Fatalf("expected new session to be valid: %s", err)
	}
}

// TestSAMLAssertionReplay: the same assertion can't be used twice.
func TestSAMLAssertionReplay(t *testing.T) {
	s := newTestSAML()
	notOnOrAfter := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	sessionNotOnOrAfter := time.Now().Add(time.Hour)
	code, err := s.createSessionFromAssertion("prov-1", testAssertionInfo("assertion-1", notOnOrAfter, &sessionNotOnOrAfter))
	if err != nil || code == "" {
		t.Fatalf("expected session to be created, got %q, %v", code, err)
	}
	if _, err := s.createSessionFromAssertion("prov-1", testAssertionInfo("assertion-1", notOnOrAfter, &sessionNotOnOrAfter)); err == nil {
		t.Fatalf("expected replayed assertion to be rejected")
	}
	if _, err := s.createSessionFromAssertion("prov-1", testAssertionInfo("assertion-2", notOnOrAfter, &sessionNotOnOrAfter)); err != nil {
		t.Fatalf("expected other assertion to be accepted: %s", err)
	}
	if _, err := s.createSessionFromAssertion("prov-1", testAssertionInfo("", notOnOrAfter, &sessionNotOnOrAfter)); err == nil {
		t.Fatalf("expected assertion without id to be rejected")
	}
	// consumed assertion ids are pruned once they can't be replayed anymore
	s.mu.Lock()
	s.consumedAssertions["prov-1/stale"] = time.Now().Add(-time.Second)
	s.mu.Unlock()
	s.CreateSession(SessionKey{ProviderID: "prov-1", SessionID: "x"}, AuthenticatedUser{ExpiresAt: time.Now().Add(time.Hour)})
	if _, ok := s.consumedAssertions["prov-1/stale"]; ok {
		t.Fatalf("expected stale consumed assertion to be pruned")
	}
}

// TestSAMLMissingSessionNotOnOrAfter: an IdP that omits SessionNotOnOrAfter
// must not crash the ACS handler.
func TestSAMLMissingSessionNotOnOrAfter(t *testing.T) {
	s := newTestSAML()
	code, err := s.createSessionFromAssertion("prov-1", testAssertionInfo("assertion-1", "", nil))
	if err != nil {
		t.Fatalf("expected session to be created: %s", err)
	}
	user, err := s.ConsumeAuthenticatedUser(Provider{ID: "prov-1"}, code)
	if err != nil {
		t.Fatalf("expected valid session: %s", err)
	}
	if user.Login != "john@example.com" {
		t.Fatalf("unexpected login: %s", user.Login)
	}
	if user.ExpiresAt.Before(time.Now().Add(DEFAULT_SESSION_DURATION - time.Minute)) {
		t.Fatalf("expected default session duration, got expiry %s", user.ExpiresAt)
	}
}
