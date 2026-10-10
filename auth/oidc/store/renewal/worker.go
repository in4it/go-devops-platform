package oidcrenewal

import (
	"fmt"
	"log"
	"time"

	"github.com/in4it/go-devops-platform/logging"
)

const WAKEUP_TIME_SECONDS = 300         // every 5 minutes we check
const DEFAULT_RENEWAL_TIME_MINUTES = 60 // every hour we want to refresh the token
const RENEWAL_RETRIES = 3               // 3 retries before we suspend a user
const RENEWAL_BACKOFF_SECONDS = 10      // time between requests to the oidc providers

// backoffSleep waits between requests to the oidc providers
var backoffSleep = func() {
	time.Sleep(RENEWAL_BACKOFF_SECONDS * time.Second)
}

func (r *Renewal) Worker() {
	// do renewal
	if r.enabled {
		fmt.Printf("Starting oidc renewal worker (loglevel: %d)\n", logging.Loglevel)
	}
	for {
		if !r.enabled {
			time.Sleep(WAKEUP_TIME_SECONDS * time.Second)
			continue
		}
		r.renewAll()
		time.Sleep(WAKEUP_TIME_SECONDS * time.Second)
	}
}

func (r *Renewal) renewAll() {
	deletedEntries := r.oidcStore.CleanupOAuth2DataForAllEntries()
	if deletedEntries > 0 {
		err := r.oidcStore.SaveOIDCStore()
		if err != nil {
			log.Printf("Renewal Worker: [warning] couldn't save oidc store after cleanup: %s", err)
		}
	}
	for key, oauth2Data := range r.oidcStore.GetOAuth2DataCopy() {
		logging.DebugLog(fmt.Errorf("running canRenew of %s", oauth2Data.ID))
		// can we renew? Do we have expiration date and it is expired?
		canRenew, oidcProvider, discovery, err := canRenew(r.renewalTime, oauth2Data, r.oidcStore, r.oidcProviders)
		if err != nil {
			log.Printf("Renewal Worker: [warning] needsRenewal: %s", err)
		}
		if canRenew {
			logging.DebugLog(fmt.Errorf("we can renew %s", oauth2Data.ID))
			userDisabled := r.renew(discovery, key, oauth2Data, oidcProvider) // error logging within function
			if userDisabled {
				r.disableUser(oauth2Data.ID)
			}
			backoffSleep() // only wait after a request to the oidc provider
		}
	}
}

// disableUser disables the connections of the user with the given oidc id
// after token renewal failed
func (r *Renewal) disableUser(oidcID string) {
	if r.userStore == nil {
		return
	}
	user, err := r.userStore.GetUserByOIDCIDs([]string{oidcID})
	if err != nil {
		logging.ErrorLog(fmt.Errorf("renewal Worker: no user found with oidc id %s", oidcID))
		return
	}
	logging.DebugLog(fmt.Errorf("disable user with oidc id %s", oidcID))
	if r.userStore.UserHooks.DisableFunc != nil {
		err = r.userStore.UserHooks.DisableFunc(r.storage, user)
		if err != nil {
			logging.ErrorLog(fmt.Errorf("renewal Worker: could not disable connections for userID %s: %s", user.ID, err))
			return
		}
	}
	user.ConnectionsDisabledOnAuthFailure = true
	err = r.userStore.UpdateUser(user)
	if err != nil {
		logging.ErrorLog(fmt.Errorf("renewal Worker: could not update connectionsDisabledOnAuthFailure for userID %s: %s", user.ID, err))
	}
}
