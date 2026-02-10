package licensing

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripperFunc lets us stub http.Client.Do() without spinning up a server.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func httpResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func Test_isOnAzure(t *testing.T) {
	origIP := MetadataIP
	MetadataIP = "169.254.169.254"
	t.Cleanup(func() { MetadataIP = origIP })

	t.Run("returns true on 200 from /metadata/versions and sends Metadata header", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Fatalf("expected GET, got %s", req.Method)
				}
				if req.URL.String() != "http://169.254.169.254/metadata/versions" {
					t.Fatalf("unexpected url: %s", req.URL.String())
				}
				if got := req.Header.Get("Metadata"); got != "true" {
					t.Fatalf("expected Metadata:true header, got %q", got)
				}
				return httpResp(200, `["2021-02-01","2025-04-07"]`), nil
			}),
		}

		if got := isOnAzure(client); got != true {
			t.Fatalf("expected true, got %v", got)
		}
	})

	t.Run("returns false on non-200", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return httpResp(404, `{"error":"not found"}`), nil
			}),
		}

		if got := isOnAzure(client); got != false {
			t.Fatalf("expected false, got %v", got)
		}
	})

	t.Run("returns false on transport error", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network down")
			}),
		}

		if got := isOnAzure(client); got != false {
			t.Fatalf("expected false, got %v", got)
		}
	})
}

func Test_GetMaxUsersAzure(t *testing.T) {
	tests := []struct {
		name         string
		instanceType string
		want         int
	}{
		{"empty defaults to 3", "", 3},
		// typical Azure VM size string contains CPU count as the first number: D2s_v3 -> 2 -> 50 users
		{"parses cpu count from Standard_D2s_v3", "Standard_D2s_v3", 50},
		// special-case: if first extracted number is 0 => 15
		{"cpu count 0 special-cases to 15", "Standard_D0s_v3", 15},
		// your code strips leading version prefix matching ^.*v[0-9]+#
		{"strips version prefix", "foo-v12#Standard_D4s_v3", 100},
		{"no digits falls back to 3", "Standard_Whatever", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetMaxUsersAzure(tt.instanceType); got != tt.want {
				t.Fatalf("GetMaxUsersAzure(%q)=%d, want %d", tt.instanceType, got, tt.want)
			}
		})
	}
}

func Test_getAzureInstanceType(t *testing.T) {
	origIP := MetadataIP
	MetadataIP = "169.254.169.254"
	t.Cleanup(func() { MetadataIP = origIP })

	// Realistic (trimmed) sample based on Microsoft Learn IMDS "instance" response:
	// it returns an object with top-level "compute", and compute includes "vmSize" and "plan".
	const instanceJSON = `{
	  "compute": {
	    "azEnvironment": "AZUREPUBLICCLOUD",
	    "location": "westus",
	    "name": "examplevmname",
	    "plan": { "name": "planName", "product": "planProduct", "publisher": "planPublisher" },
	    "vmSize": "Standard_D2s_v3"
	  }
	}`

	t.Run("returns vmSize on 200 and valid JSON", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != "http://169.254.169.254/metadata/instance?api-version=2021-02-01" {
					t.Fatalf("unexpected url: %s", req.URL.String())
				}
				if got := req.Header.Get("Metadata"); got != "true" {
					t.Fatalf("expected Metadata:true header, got %q", got)
				}
				return httpResp(200, instanceJSON), nil
			}),
		}

		if got := getAzureInstanceType(client); got != "Standard_D2s_v3" {
			t.Fatalf("expected Standard_D2s_v3, got %q", got)
		}
	})

	t.Run("returns empty string on non-200", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return httpResp(500, `{"error":"boom"}`), nil
			}),
		}
		if got := getAzureInstanceType(client); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("returns empty string on invalid JSON", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return httpResp(200, `{not-json`), nil
			}),
		}
		if got := getAzureInstanceType(client); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})
}

func Test_getAzureInstancePlan(t *testing.T) {
	origIP := MetadataIP
	MetadataIP = "169.254.169.254"
	t.Cleanup(func() { MetadataIP = origIP })

	// Realistic (trimmed) sample based on Microsoft Learn IMDS "compute" endpoint:
	// /metadata/instance/compute returns the compute object (not wrapped).
	const computeJSON = `{
	  "azEnvironment": "AZUREPUBLICCLOUD",
	  "location": "westus",
	  "name": "examplevmname",
	  "plan": { "name": "planName", "product": "planProduct", "publisher": "planPublisher" },
	  "vmSize": "Standard_D2s_v3"
	}`

	t.Run("returns plan on 200 and valid JSON", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01" {
					t.Fatalf("unexpected url: %s", req.URL.String())
				}
				if got := req.Header.Get("Metadata"); got != "true" {
					t.Fatalf("expected Metadata:true header, got %q", got)
				}
				return httpResp(200, computeJSON), nil
			}),
		}

		got := getAzureInstancePlan(client)
		if got.Name != "planName" || got.Product != "planProduct" || got.Publisher != "planPublisher" {
			t.Fatalf("unexpected plan: %#v", got)
		}
	})

	t.Run("returns empty Plan on invalid JSON", func(t *testing.T) {
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return httpResp(200, `{not-json`), nil
			}),
		}
		got := getAzureInstancePlan(client)
		if got != (Plan{}) {
			t.Fatalf("expected empty plan, got %#v", got)
		}
	})

	t.Run("returns empty Plan on read error", func(t *testing.T) {
		// Force ReadAll to fail by returning a Body that errors.
		errBody := io.NopCloser(&errorReader{})
		client := http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Body:       errBody,
					Header:     make(http.Header),
				}, nil
			}),
		}
		got := getAzureInstancePlan(client)
		if got != (Plan{}) {
			t.Fatalf("expected empty plan, got %#v", got)
		}
	})
}

type errorReader struct{}

func (r *errorReader) Read(_ []byte) (int, error) { return 0, errors.New("read failed") }
func (r *errorReader) Close() error               { return nil }

// Optional: a sanity test that the fake client can verify headers across endpoints.
func Test_fakeClientRejectsMissingMetadataHeader(t *testing.T) {
	origIP := MetadataIP
	MetadataIP = "169.254.169.254"
	t.Cleanup(func() { MetadataIP = origIP })

	// Here we simulate a transport that enforces the header; the production code SHOULD set it.
	client := http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Metadata") != "true" {
				return httpResp(400, `{"error":"missing Metadata header"}`), nil
			}
			return httpResp(200, `[]`), nil
		}),
	}

	if got := isOnAzure(client); got != true {
		// If this fails, your code isn't setting Metadata:true for /metadata/versions.
		t.Fatalf("expected true, got %v", got)
	}
}

// Small helper if you want to create responses with bytes.Reader bodies in other tests.
func bodyFromBytes(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}
