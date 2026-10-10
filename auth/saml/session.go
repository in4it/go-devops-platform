package saml

import (
	"fmt"
	"time"
)

// SESSION_REDEEM_TTL is how long the code handed to the browser after the ACS
// callback can be exchanged for a token. The code can only be used once.
const SESSION_REDEEM_TTL = 5 * time.Minute

// DEFAULT_SESSION_DURATION is used when the IdP doesn't send a
// SessionNotOnOrAfter in the AuthnStatement.
const DEFAULT_SESSION_DURATION = 72 * time.Hour

type session struct {
	user      AuthenticatedUser
	createdAt time.Time
}

// GetAuthenticatedUser returns the authenticated user of a session without
// consuming it. Use ConsumeAuthenticatedUser to redeem a session.
func (s *saml) GetAuthenticatedUser(provider Provider, sessionID string) (AuthenticatedUser, error) {
	sessionKey := SessionKey{
		ProviderID: provider.ID,
		SessionID:  sessionID,
	}
	s.mu.Lock()
	sess, ok := s.sessions[sessionKey]
	s.mu.Unlock()
	if !ok {
		return AuthenticatedUser{}, fmt.Errorf("session not found")
	}
	return validateSession(sess, time.Now())
}

// ConsumeAuthenticatedUser returns the authenticated user of a session and
// deletes the session, so the same code can't be redeemed twice.
func (s *saml) ConsumeAuthenticatedUser(provider Provider, sessionID string) (AuthenticatedUser, error) {
	sessionKey := SessionKey{
		ProviderID: provider.ID,
		SessionID:  sessionID,
	}
	s.mu.Lock()
	sess, ok := s.sessions[sessionKey]
	if ok {
		delete(s.sessions, sessionKey)
	}
	s.mu.Unlock()
	if !ok {
		return AuthenticatedUser{}, fmt.Errorf("session not found")
	}
	return validateSession(sess, time.Now())
}

func validateSession(sess session, now time.Time) (AuthenticatedUser, error) {
	if now.After(sess.createdAt.Add(SESSION_REDEEM_TTL)) {
		return sess.user, fmt.Errorf("session is expired")
	}
	if sess.user.ExpiresAt.Before(now) {
		return sess.user, fmt.Errorf("session is expired")
	}
	return sess.user, nil
}

func (s *saml) CreateSession(key SessionKey, value AuthenticatedUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneExpired(now)
	s.sessions[key] = session{user: value, createdAt: now}
}

// pruneExpired removes sessions that can't be redeemed anymore and consumed
// assertion ids that can't be replayed anymore. Must be called with s.mu held.
func (s *saml) pruneExpired(now time.Time) {
	for k, sess := range s.sessions {
		if now.After(sess.createdAt.Add(SESSION_REDEEM_TTL)) {
			delete(s.sessions, k)
		}
	}
	for k, expiresAt := range s.consumedAssertions {
		if now.After(expiresAt) {
			delete(s.consumedAssertions, k)
		}
	}
}
