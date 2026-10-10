package oidcstore

import (
	"slices"
	"time"

	"github.com/in4it/go-devops-platform/auth/oidc"
)

// PENDING_STATE_TTL is how long a state without token (a login that was
// started, but not completed yet) is kept
const PENDING_STATE_TTL = 10 * time.Minute

// MAX_PENDING_STATES is the maximum number of states without token. When a new
// state is saved and there are more, the oldest ones are dropped.
var MAX_PENDING_STATES = 1000

func (store *Store) CleanupOAuth2DataForAllEntries() int {
	deleted := 0
	for _, oauthData := range store.GetOAuth2DataCopy() {
		deleted += store.CleanupOAuth2Data(oauthData)
	}
	return deleted
}

func (store *Store) CleanupOAuth2Data(oauthData oidc.OAuthData) int {
	keysToDelete1 := []string{}
	keysToDelete2 := []string{}
	keysToDelete3 := []string{}
	store.Mu.Lock()
	defer store.Mu.Unlock()
	for k := range store.OAuth2Data {
		if oauthData.CreatedAt.After(store.OAuth2Data[k].CreatedAt) {
			// cleanup old oauth2 data that might be duplicates (same subject & oidc provider, but older tokens)
			// (only for entries with a subject: pending states without token have none)
			if oauthData.Subject != "" && store.OAuth2Data[k].ID != oauthData.ID && store.OAuth2Data[k].OIDCProviderID == oauthData.OIDCProviderID && store.OAuth2Data[k].Subject == oauthData.Subject {
				keysToDelete1 = append(keysToDelete1, k)
			}
			// cleanup oauthdata with the same email address
			if oauthData.UserInfo.Email != "" && store.OAuth2Data[k].ID != oauthData.ID && store.OAuth2Data[k].UserInfo.Email == oauthData.UserInfo.Email {
				keysToDelete3 = append(keysToDelete3, k)
			}
		}
		// cleanup old oauth2 data that doesn't have a token and is stale
		if store.OAuth2Data[k].Token.AccessToken == "" && store.OAuth2Data[k].CreatedAt.Add(PENDING_STATE_TTL).Before(time.Now()) {
			keysToDelete2 = append(keysToDelete2, k)
		}
	}
	keysToDelete := []string{}
	keysToDelete = append(keysToDelete, keysToDelete1...)
	keysToDelete = append(keysToDelete, keysToDelete2...)
	keysToDelete = append(keysToDelete, keysToDelete3...)
	slices.Sort(keysToDelete)

	for _, key := range slices.Compact(keysToDelete) {
		delete(store.OAuth2Data, key)
	}
	return len(keysToDelete)
}

// prunePendingStates removes stale states without a token, and the oldest
// states without a token when there are more than MAX_PENDING_STATES - 1, to
// make room for a new one. Must be called with store.Mu held.
func (store *Store) prunePendingStates(now time.Time) {
	type pendingState struct {
		key       string
		createdAt time.Time
	}
	pending := []pendingState{}
	for k, oauthData := range store.OAuth2Data {
		if oauthData.Token.AccessToken != "" {
			continue
		}
		if oauthData.CreatedAt.Add(PENDING_STATE_TTL).Before(now) {
			delete(store.OAuth2Data, k)
			continue
		}
		pending = append(pending, pendingState{key: k, createdAt: oauthData.CreatedAt})
	}
	if len(pending) < MAX_PENDING_STATES {
		return
	}
	slices.SortFunc(pending, func(a, b pendingState) int {
		return a.createdAt.Compare(b.createdAt)
	})
	for _, p := range pending[:len(pending)-MAX_PENDING_STATES+1] {
		delete(store.OAuth2Data, p.key)
	}
}
