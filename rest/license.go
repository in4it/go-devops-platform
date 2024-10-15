package rest

import (
	"encoding/json"
	"fmt"
	"net/http"

	licensing "github.com/in4it/go-devops-platform/licensing"
)

func (c *Context) licenseHandler(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("action") == "get-more" {
		c.LicenseUserCount = licensing.RefreshLicense(c.Storage.Client, c.CloudType, c.LicenseUserCount)
	}

	currentUserCount := c.UserStore.UserCount()
	licenseResponse := LicenseResponse{LicenseUserCount: c.LicenseUserCount, CurrentUserCount: currentUserCount, CloudType: c.CloudType}

	if r.PathValue("action") == "get-more" {
		licenseResponse.Key = licensing.GetLicenseKey(c.Storage.Client, c.CloudType)
	}

	out, err := json.Marshal(licenseResponse)
	if err != nil {
		c.returnError(w, fmt.Errorf("oidcProviders marshal error"), http.StatusBadRequest)
		return
	}
	c.write(w, out)
}
