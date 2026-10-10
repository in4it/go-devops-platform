package saml

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
)

// DEFAULT_ASSERTION_TTL is how long a consumed assertion id is remembered when
// the assertion has no (parsable) Conditions NotOnOrAfter.
const DEFAULT_ASSERTION_TTL = 24 * time.Hour

// MAX_ASSERTION_TTL bounds how long a consumed assertion id is remembered.
const MAX_ASSERTION_TTL = 7 * 24 * time.Hour

// markAssertionConsumed records the assertion id and returns an error if the
// assertion was already used (replay).
func (s *saml) markAssertionConsumed(providerID string, assertionInfo *saml2.AssertionInfo, now time.Time) error {
	if assertionInfo == nil || len(assertionInfo.Assertions) == 0 || assertionInfo.Assertions[0].ID == "" {
		return fmt.Errorf("assertion id missing")
	}
	assertion := assertionInfo.Assertions[0]
	expiresAt := now.Add(DEFAULT_ASSERTION_TTL)
	if assertion.Conditions != nil && assertion.Conditions.NotOnOrAfter != "" {
		if notOnOrAfter, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter); err == nil {
			expiresAt = notOnOrAfter
		}
	}
	if expiresAt.After(now.Add(MAX_ASSERTION_TTL)) {
		expiresAt = now.Add(MAX_ASSERTION_TTL)
	}
	key := providerID + "/" + assertion.ID

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumedAssertions == nil {
		s.consumedAssertions = make(map[string]time.Time)
	}
	if consumedUntil, ok := s.consumedAssertions[key]; ok && !now.After(consumedUntil) {
		return fmt.Errorf("assertion already used")
	}
	s.consumedAssertions[key] = expiresAt
	return nil
}

// createSessionFromAssertion creates a single-use session for a validated
// assertion and returns the session id (the code passed to the browser).
func (s *saml) createSessionFromAssertion(providerID string, assertionInfo *saml2.AssertionInfo) (string, error) {
	now := time.Now()
	err := s.markAssertionConsumed(providerID, assertionInfo, now)
	if err != nil {
		return "", err
	}

	notAfter := now.Add(DEFAULT_SESSION_DURATION)
	if assertionInfo.SessionNotOnOrAfter != nil {
		notAfter = *assertionInfo.SessionNotOnOrAfter
	}

	randomString, err := getRandomString(128)
	if err != nil {
		return "", fmt.Errorf("could not create session: %s", err)
	}
	sessionKey := SessionKey{
		ProviderID: providerID,
		SessionID:  randomString,
	}
	s.CreateSession(sessionKey, AuthenticatedUser{
		ID:        uuid.New().String(),
		Login:     assertionInfo.NameID,
		ExpiresAt: notAfter,
	})
	return sessionKey.SessionID, nil
}
