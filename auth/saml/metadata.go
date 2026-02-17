package saml

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/russellhaering/gosaml2/types"
)

const (
	maxMetadataBytes = 2 << 20 // 2 MiB
	maxURLLength     = 2048
	maxRedirects     = 3

	requestTimeout        = 10 * time.Second
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 5 * time.Second
)

// Cloud instance metadata service IP (AWS/Azure/GCP commonly use this)
var blockedMetadataIPs = map[string]bool{
	"169.254.169.254": true,
}

// GCP also commonly exposes metadata via this hostname (which resolves to 169.254.169.254)
var blockedMetadataHostnames = map[string]bool{
	"metadata.google.internal":  true,
	"metadata.google.internal.": true,
}

func (s *saml) HasValidMetadataURL(metadataURL string) (bool, error) {
	if strings.TrimSpace(metadataURL) == "" {
		return false, errors.New("metadata URL is empty")
	}
	if len(metadataURL) > maxURLLength {
		return false, fmt.Errorf("metadata URL too long (>%d chars)", maxURLLength)
	}

	metadataURLParsed, err := url.Parse(metadataURL)
	if err != nil {
		return false, fmt.Errorf("url parse error: %w", err)
	}

	_, err = getMetadata(metadataURLParsed)
	if err != nil {
		return false, fmt.Errorf("fetch metadata error: %w", err)
	}
	return true, nil
}

func basicURLChecks(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q (only http/https allowed)", u.Scheme)
	}
	if u.Hostname() == "" {
		return errors.New("metadata URL missing host")
	}
	if u.User != nil {
		return errors.New("userinfo (username/password) not allowed in metadata URL")
	}
	if u.Fragment != "" {
		return errors.New("fragments are not allowed in metadata URL")
	}
	return nil
}

func rejectCloudMetadata(u *url.URL) error {
	host := strings.ToLower(u.Hostname())

	if blockedMetadataHostnames[host] {
		return fmt.Errorf("blocked cloud metadata hostname: %s", host)
	}

	if ip := net.ParseIP(host); ip != nil {
		if blockedMetadataIPs[ip.String()] {
			return fmt.Errorf("blocked cloud metadata IP: %s", ip.String())
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("dns lookup failed for host %q: %w", host, err)
	}
	for _, ip := range ips {
		if blockedMetadataIPs[ip.String()] {
			return fmt.Errorf("blocked cloud metadata (host %q resolves to %s)", host, ip.String())
		}
	}
	return nil
}

func getMetadata(metadataURL *url.URL) (types.EntityDescriptor, error) {
	metadata := types.EntityDescriptor{}

	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			// Re-apply basic checks + metadata blocking to the redirect target
			if err := basicURLChecks(req.URL); err != nil {
				return err
			}
			if err := rejectCloudMetadata(req.URL); err != nil {
				return err
			}
			return nil
		},
	}

	if err := basicURLChecks(metadataURL); err != nil {
		return metadata, err
	}
	if err := rejectCloudMetadata(metadataURL); err != nil {
		return metadata, err
	}

	req, err := http.NewRequest(http.MethodGet, metadataURL.String(), nil)
	if err != nil {
		return metadata, fmt.Errorf("can't build request: %w", err)
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml;q=0.9, */*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return metadata, fmt.Errorf("can't retrieve saml metadata: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return metadata, fmt.Errorf("metadata fetch returned %s", res.Status)
	}

	rawMetadata, err := readCapped(res.Body, maxMetadataBytes)
	if err != nil {
		return metadata, err
	}

	err = xml.Unmarshal(rawMetadata, &metadata)
	if err != nil {
		return metadata, fmt.Errorf("can't decode saml cert data: %s", err)
	}
	return metadata, nil
}

func readCapped(r io.Reader, max int64) ([]byte, error) {
	lr := io.LimitReader(r, max+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("can't read saml metadata: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("metadata too large (>%d bytes)", max)
	}
	return b, nil
}
