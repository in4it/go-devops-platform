package licensing

import (
	"fmt"
	"net/http"

	"github.com/in4it/go-devops-platform/logging"
	"github.com/in4it/go-devops-platform/storage"
)

func GetMaxUsersBYOLNoCloud(client http.Client, storage storage.ReadWriter) int {
	userLicense := 3

	licenseKey, err := getLicenseKeyFromFile(storage)
	if err != nil {
		return 3
	}

	license, err := getLicense(client, licenseKey)
	if err != nil {
		logging.DebugLog(fmt.Errorf("getLicense error: %s", err))
		return userLicense
	}

	return license.Users
}
