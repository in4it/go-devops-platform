package rest

import (
	"fmt"
	"time"

	"github.com/in4it/go-devops-platform/auth/oidc"
	oidcstore "github.com/in4it/go-devops-platform/auth/oidc/store"
	oidcrenewal "github.com/in4it/go-devops-platform/auth/oidc/store/renewal"
	"github.com/in4it/go-devops-platform/auth/provisioning/scim"
	"github.com/in4it/go-devops-platform/auth/saml"
	licensing "github.com/in4it/go-devops-platform/licensing"
	"github.com/in4it/go-devops-platform/logging"
	"github.com/in4it/go-devops-platform/rest/login"
	"github.com/in4it/go-devops-platform/storage"
	"github.com/in4it/go-devops-platform/users"
)

func NewContext(storage storage.Iface, serverType string, userStore *users.UserStore, scimInstance scim.Iface, licenseUserCount int, cloudType string, apps map[string]AppClient) (*Context, error) {
	return newContextWithParams(storage, serverType, userStore, scimInstance, licenseUserCount, cloudType, apps)
}

func newContext(storage storage.Iface, serverType string) (*Context, error) {
	userStore, err := users.NewUserStore(storage, 100)
	if err != nil {
		return &Context{}, fmt.Errorf("userstore initialization error: %s", err)
	}
	return newContextWithParams(storage, serverType, userStore, scim.New(storage, userStore, "", nil, nil), 100, "", map[string]AppClient{})
}

func newContextWithParams(storage storage.Iface, serverType string, userStore *users.UserStore, scimInstance scim.Iface, licenseUserCount int, cloudType string, apps map[string]AppClient) (*Context, error) {
	c, err := GetConfig(storage)
	if err != nil {
		return c, fmt.Errorf("getConfig error: %s", err)
	}
	c.ServerType = serverType

	c.Storage = &Storage{
		Client: storage,
	}

	c.JWTKeys, err = getJWTKeys(storage)
	if err != nil {
		return c, fmt.Errorf("getJWTKeys error: %s", err)
	}
	c.OIDCStore, err = oidcstore.NewStore(storage)
	if err != nil {
		return c, fmt.Errorf("getOIDCStore error: %s", err)
	}
	if c.OIDCProviders == nil {
		c.OIDCProviders = []oidc.OIDCProvider{}
	}

	c.LicenseUserCount = licenseUserCount
	c.CloudType = cloudType

	go func() { // run license refresh
		logging.DebugLog(fmt.Errorf("starting license refresh in background (current licenses: %d, cloud type: %s)", c.LicenseUserCount, c.CloudType))
		for {
			time.Sleep(time.Hour * 24)
			newLicenseCount := licensing.RefreshLicense(storage, c.CloudType, c.LicenseUserCount)
			if newLicenseCount != c.LicenseUserCount {
				logging.InfoLog(fmt.Sprintf("License changed from %d users to %d users", c.LicenseUserCount, newLicenseCount))
				c.LicenseUserCount = newLicenseCount
			}
		}
	}()

	c.UserStore = userStore

	c.OIDCRenewal, err = oidcrenewal.NewRenewal(storage, c.TokenRenewalTimeMinutes, c.LogLevel, c.EnableOIDCTokenRenewal, c.OIDCStore, c.OIDCProviders, c.UserStore)
	if err != nil {
		return c, fmt.Errorf("oidcrenewal init error: %s", err)
	}

	if c.LoginAttempts == nil {
		c.LoginAttempts = make(login.Attempts)
	}

	if c.SCIM == nil {
		c.SCIM = &SCIM{
			Client:     scimInstance,
			Token:      "",
			EnableSCIM: false,
		}
	} else {
		c.SCIM.Client = scimInstance
	}
	if c.SAML == nil {
		providers := []saml.Provider{}
		c.SAML = &SAML{
			Client:    saml.New(&providers, storage, &c.Protocol, &c.Hostname),
			Providers: &providers,
		}
	} else {
		c.SAML.Client = saml.New(c.SAML.Providers, storage, &c.Protocol, &c.Hostname)
	}

	c.Apps = &Apps{
		Clients: apps,
	}

	return c, nil
}

func getEmptyContext(appDir string) (*Context, error) {
	randomString, err := oidc.GetRandomString(64)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate random string for local kid")
	}
	c := &Context{
		AppDir:                  appDir,
		JWTKeysKID:              randomString,
		TokenRenewalTimeMinutes: oidcrenewal.DEFAULT_RENEWAL_TIME_MINUTES,
		LogLevel:                logging.LOG_ERROR,
		SCIM:                    &SCIM{EnableSCIM: false},
		SAML:                    &SAML{Providers: &[]saml.Provider{}},
	}
	return c, nil
}
