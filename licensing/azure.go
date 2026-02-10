package licensing

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"github.com/in4it/go-devops-platform/logging"
	"github.com/in4it/go-devops-platform/storage"
)

func isOnAzure(client http.Client) bool {
	req, err := http.NewRequest("GET", "http://"+MetadataIP+"/metadata/versions", nil)
	if err != nil {
		return false
	}

	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func GetMaxUsersAzure(instanceType string) int {
	if instanceType == "" {
		return 3
	}
	// patterns
	versionPattern := regexp.MustCompile(`^.*v[0-9]+#`)
	cpuPattern := regexp.MustCompile("[0-9]+")

	// extract amount of CPUs
	instanceTypeNoVersion := versionPattern.ReplaceAllString(instanceType, "")

	instanceTypeCPUs := cpuPattern.FindAllString(instanceTypeNoVersion, -1)

	if len(instanceTypeCPUs) > 0 {
		instanceTypeCPUCount, err := strconv.Atoi(instanceTypeCPUs[0])
		if err != nil {
			return 3
		}
		if instanceTypeCPUCount == 0 {
			return 15
		}
		return instanceTypeCPUCount * 25
	}

	return 3
}
func getAzureInstanceType(client http.Client) string {
	metadataEndpoint := "http://" + MetadataIP + "/metadata/instance?api-version=2021-02-01"
	req, err := http.NewRequest("GET", metadataEndpoint, nil)
	if err != nil {
		return ""
	}

	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	var instanceMetadata AzureInstanceMetadata
	err = json.Unmarshal(bodyBytes, &instanceMetadata)
	if err != nil {
		return ""
	}
	return instanceMetadata.Compute.VMSize
}

func getAzureInstancePlan(client http.Client) Plan {
	instanceComputeMetadata := getAzureComputeMetadata(client)
	return instanceComputeMetadata.Plan
}

func getAzureComputeMetadata(client http.Client) Compute {
	metadataEndpoint := "http://" + MetadataIP + "/metadata/instance/compute?api-version=2021-02-01"
	req, err := http.NewRequest("GET", metadataEndpoint, nil)
	if err != nil {
		return Compute{}
	}

	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return Compute{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return Compute{}
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Compute{}
	}
	var instanceComputeMetadata Compute
	err = json.Unmarshal(bodyBytes, &instanceComputeMetadata)
	if err != nil {
		return Compute{}
	}
	return instanceComputeMetadata
}

func GetMaxUsersAzureBYOL(client http.Client, storage storage.ReadWriter) int {
	userLicense := 3

	licenseKey, err := getAzureLicenseKey(storage, client)
	if err != nil {
		logging.DebugLog(fmt.Errorf("get azure license error: %s", err))
		return userLicense
	}

	license, err := getLicense(client, licenseKey)
	if err != nil {
		logging.DebugLog(fmt.Errorf("getLicense error: %s", err))
		return userLicense
	}

	return license.Users
}

func getAzureLicenseKey(storage storage.ReadWriter, client http.Client) (string, error) {
	identifier, err := getAzureIdentifier(client)
	if err != nil {
		logging.DebugLog(fmt.Errorf("License generation error (identifier error): %s", err))
		return "", err
	}

	licenseKey, err := getLicenseKeyFromFile(storage)
	if err != nil {
		return "", err
	}

	return generateLicenseKey(licenseKey, identifier), nil
}

func getAzureIdentifier(client http.Client) (string, error) {
	computeMetadata := getAzureComputeMetadata(client)
	if computeMetadata.VMID != "" {
		return computeMetadata.VMID, nil
	}
	return "", fmt.Errorf("could not get identifier from azure metadata")
}
