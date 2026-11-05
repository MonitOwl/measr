package registry

import (
	"net/http"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Options returns the options to access registries with the credentials of the
// default keychain. The registries listed in insecure, e.g. "localhost:5000",
// are accessed over plain HTTP.
func Options(insecure []string) []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(newTransport(insecure)),
	}
}

// transport sends the requests to insecure registries over plain HTTP, and all
// the others over HTTPS.
type transport struct {
	insecure []string
	base     http.RoundTripper
}

// newTransport returns a transport based on [http.DefaultTransport], so that it
// honours the proxy environment variables.
func newTransport(insecure []string) http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &transport{insecure: insecure, base: http.DefaultTransport}
	}
	return &transport{insecure: insecure, base: base.Clone()}
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL != nil && t.isInsecure(req.URL.Host) {
		req = req.Clone(req.Context())
		req.URL.Scheme = "http"
	}
	return t.base.RoundTrip(req)
}

func (t *transport) isInsecure(host string) bool {
	return slices.ContainsFunc(t.insecure, func(h string) bool {
		return strings.EqualFold(h, host)
	})
}
