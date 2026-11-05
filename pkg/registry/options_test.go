package registry_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/MonitOwl/measr/pkg/registry"
)

func TestOptions(t *testing.T) {
	t.Parallel()

	if opts := registry.Options([]string{"localhost:5000"}); len(opts) != 2 {
		t.Fatalf("expected 2 remote options, got %d", len(opts))
	}
}

func TestRegistryTransport_RoundTrip(t *testing.T) {
	t.Parallel()

	// a plain HTTP server: requests with the https scheme must be downgraded.
	httpServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("expected non-TLS plain HTTP connection")
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok-plain-http"))
	}))
	defer httpServer.Close()

	serverURL, err := url.Parse(httpServer.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	transport := registry.NewTransport([]string{serverURL.Host})

	client := &http.Client{Transport: transport}

	req, err := http.NewRequest(http.MethodGet, "https://"+serverURL.Host+"/v2/", nil)
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "ok-plain-http" {
		t.Errorf("response body = %q, want 'ok-plain-http'", string(body))
	}
}
