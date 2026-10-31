package image_test

import (
	"archive/tar"
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/MonitOwl/measr/pkg/image"
)

// newRegistry starts an in-memory registry and returns its host.
func newRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// newImage returns an image holding a single file with the given content.
func newImage(t *testing.T, filePath, content string) v1.Image {
	t.Helper()
	layer := createTarLayer(t, []tarEntry{
		{name: filePath, mode: 0o755, typeflag: tar.TypeReg, body: []byte(content)},
	})
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestMeasureImageReturnsManifestDigest(t *testing.T) {
	t.Parallel()

	ref := newRegistry(t) + "/app:1.0"
	img := newImage(t, "bin/app", "app")
	tag, err := name.NewTag(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	want, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	measured, err := image.NewMeasurer().MeasureImage(context.Background(), ref)
	if err != nil {
		t.Fatalf("MeasureImage: %v", err)
	}
	if measured.Reference != ref {
		t.Errorf("reference: got %s, want %s", measured.Reference, ref)
	}
	if measured.Digest != want.String() {
		t.Errorf("digest: got %s, want the manifest digest %s", measured.Digest, want)
	}
	if len(measured.Files) != 1 || measured.Files[0].Path() != "/bin/app" {
		t.Errorf("files: got %v, want /bin/app", measured.Files)
	}
}

func TestMeasureImageReturnsIndexDigest(t *testing.T) {
	t.Parallel()

	ref := newRegistry(t) + "/app:1.0"
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add:        newImage(t, "bin/arm", "arm"),
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		},
		mutate.IndexAddendum{
			Add:        newImage(t, "bin/amd", "amd"),
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		},
	)
	tag, err := name.NewTag(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.WriteIndex(tag, idx); err != nil {
		t.Fatal(err)
	}
	want, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		platform v1.Platform
		file     string
	}{
		{v1.Platform{OS: "linux", Architecture: "amd64"}, "/bin/amd"},
		{v1.Platform{OS: "linux", Architecture: "arm64"}, "/bin/arm"},
	}
	for _, tt := range tests {
		t.Run(tt.platform.String(), func(t *testing.T) {
			t.Parallel()

			measurer := image.NewMeasurer(remote.WithPlatform(tt.platform))
			measured, measureErr := measurer.MeasureImage(context.Background(), ref)
			if measureErr != nil {
				t.Fatalf("MeasureImage: %v", measureErr)
			}
			if measured.Digest != want.String() {
				t.Errorf("digest: got %s, want the index digest %s", measured.Digest, want)
			}
			if len(measured.Files) != 1 || measured.Files[0].Path() != tt.file {
				t.Errorf("files: got %v, want %s", measured.Files, tt.file)
			}
		})
	}
}
