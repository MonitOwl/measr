package image_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/MonitOwl/measr/pkg/image"
)

func TestSupportedHashAlgos(t *testing.T) {
	t.Parallel()

	algos := image.SupportedHashAlgos()
	if len(algos) != 4 {
		t.Fatalf("expected 4 supported hash algos, got %d", len(algos))
	}

	// the returned slice is a copy.
	algos[0] = crypto.MD5
	if image.SupportedHashAlgos()[0] == crypto.MD5 {
		t.Error("SupportedHashAlgos did not return a copy")
	}
}

func TestHashFile(t *testing.T) {
	t.Parallel()

	content := []byte("test content for hashing")
	digests, err := image.HashFile(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("HashFile() error = %v", err)
	}

	if len(digests) != len(image.SupportedHashAlgos()) {
		t.Fatalf("expected %d digests, got %d", len(image.SupportedHashAlgos()), len(digests))
	}

	expectedSHA256 := sha256.Sum256(content)
	gotSHA256 := digests[crypto.SHA256]
	if !bytes.Equal(gotSHA256, expectedSHA256[:]) {
		t.Errorf("SHA256 digest mismatch: got %x, want %x", gotSHA256, expectedSHA256)
	}
}

func createTarLayer(t *testing.T, entries []tarEntry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Typeflag: e.typeflag,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader error: %v", err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write body error: %v", err)
			}
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar close error: %v", err)
	}

	raw := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatalf("LayerFromOpener error: %v", err)
	}
	return layer
}

type tarEntry struct {
	name     string
	mode     int64
	typeflag byte
	body     []byte
	linkname string
}

func TestProcessLayer_Whiteouts(t *testing.T) {
	t.Parallel()

	merged := make(map[string]*image.FileMeasurement)

	// Layer 1: add /etc/app.conf, /etc/secrets.txt, /usr/bin/tool
	layer1 := createTarLayer(t, []tarEntry{
		{name: "etc/app.conf", mode: 0o644, typeflag: tar.TypeReg, body: []byte("config v1")},
		{name: "etc/secrets.txt", mode: 0o600, typeflag: tar.TypeReg, body: []byte("secret")},
		{name: "usr/bin/tool", mode: 0o755, typeflag: tar.TypeReg, body: []byte("tool binary")},
		{name: "etc/", mode: 0o755, typeflag: tar.TypeDir, body: nil},
	})

	rc1, openErr1 := layer1.Uncompressed()
	if openErr1 != nil {
		t.Fatalf("open layer1: %v", openErr1)
	}
	defer rc1.Close()

	if procErr := image.ProcessLayer(rc1, "layer1-digest", merged); procErr != nil {
		t.Fatalf("processLayer 1 failed: %v", procErr)
	}

	if len(merged) != 3 {
		t.Fatalf("expected 3 files in merged, got %d", len(merged))
	}
	if _, ok := merged["/etc/app.conf"]; !ok {
		t.Error("/etc/app.conf not found")
	}

	// Layer 2: delete /etc/secrets.txt via whiteout and update /etc/app.conf
	layer2 := createTarLayer(t, []tarEntry{
		{name: "etc/.wh.secrets.txt", mode: 0o644, typeflag: tar.TypeReg, body: nil},
		{name: "etc/app.conf", mode: 0o644, typeflag: tar.TypeReg, body: []byte("config v2")},
	})

	rc2, openErr2 := layer2.Uncompressed()
	if openErr2 != nil {
		t.Fatalf("open layer2: %v", openErr2)
	}
	defer rc2.Close()

	if procErr := image.ProcessLayer(rc2, "layer2-digest", merged); procErr != nil {
		t.Fatalf("processLayer 2 failed: %v", procErr)
	}

	if len(merged) != 2 {
		t.Fatalf("expected 2 files in merged, got %d", len(merged))
	}
	if _, ok := merged["/etc/secrets.txt"]; ok {
		t.Error("/etc/secrets.txt should have been deleted by whiteout")
	}
	if merged["/etc/app.conf"].LayerDigest() != "layer2-digest" {
		t.Errorf("expected /etc/app.conf to be from layer2-digest, got %s", merged["/etc/app.conf"].LayerDigest())
	}

	// Layer 3: opaque whiteout on /etc directory
	layer3 := createTarLayer(t, []tarEntry{
		{name: "etc/.wh..wh..opq", mode: 0o644, typeflag: tar.TypeReg, body: nil},
		{name: "etc/new_service.conf", mode: 0o644, typeflag: tar.TypeReg, body: []byte("new service")},
	})

	rc3, openErr3 := layer3.Uncompressed()
	if openErr3 != nil {
		t.Fatalf("open layer3: %v", openErr3)
	}
	defer rc3.Close()

	if procErr := image.ProcessLayer(rc3, "layer3-digest", merged); procErr != nil {
		t.Fatalf("processLayer 3 failed: %v", procErr)
	}

	if len(merged) != 2 {
		t.Fatalf("expected 2 files in merged (/usr/bin/tool and /etc/new_service.conf), got %d", len(merged))
	}
	if _, ok := merged["/etc/app.conf"]; ok {
		t.Error("/etc/app.conf should have been deleted by opaque whiteout")
	}
	if _, ok := merged["/etc/new_service.conf"]; !ok {
		t.Error("/etc/new_service.conf not found")
	}
	if _, ok := merged["/usr/bin/tool"]; !ok {
		t.Error("/usr/bin/tool not found")
	}
}

func TestMeasure(t *testing.T) {
	t.Parallel()

	layer1 := createTarLayer(t, []tarEntry{
		{name: "bin/hello", mode: 0o755, typeflag: tar.TypeReg, body: []byte("hello world")},
	})

	img, err := mutate.AppendLayers(empty.Image, layer1)
	if err != nil {
		t.Fatalf("AppendLayers error: %v", err)
	}

	measurements, err := image.Measure(img)
	if err != nil {
		t.Fatalf("Measure error: %v", err)
	}

	if len(measurements) != 1 {
		t.Fatalf("expected 1 measurement, got %d", len(measurements))
	}

	m := measurements[0]
	if m.Path() != "/bin/hello" {
		t.Errorf("Path = %q, want /bin/hello", m.Path())
	}
	if m.Mode() != 0o755 {
		t.Errorf("Mode = %o, want 755", m.Mode())
	}

	expectedHash := sha256.Sum256([]byte("hello world"))
	if hex256, ok := m.HexDigest(crypto.SHA256); !ok || hex256 != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("SHA256 hex mismatch: got %s, want %s", hex256, hex.EncodeToString(expectedHash[:]))
	}
}

func TestMeasureImageRejectsInvalidReference(t *testing.T) {
	t.Parallel()

	_, err := image.NewMeasurer().MeasureImage(context.Background(), "invalid::reference::with::extra::colons")
	if err == nil {
		t.Error("expected error for invalid reference")
	}
}

func TestMeasureSortsByPath(t *testing.T) {
	t.Parallel()

	layer := createTarLayer(t, []tarEntry{
		{name: "usr/bin/b", mode: 0o755, typeflag: tar.TypeReg, body: []byte("b")},
		{name: "etc/a", mode: 0o644, typeflag: tar.TypeReg, body: []byte("a")},
		{name: "bin/c", mode: 0o755, typeflag: tar.TypeReg, body: []byte("c")},
	})
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("AppendLayers error: %v", err)
	}

	measurements, err := image.Measure(img)
	if err != nil {
		t.Fatalf("Measure error: %v", err)
	}
	var paths []string
	for _, m := range measurements {
		paths = append(paths, m.Path())
	}
	if !slices.Equal(paths, []string{"/bin/c", "/etc/a", "/usr/bin/b"}) {
		t.Fatalf("got paths %v, want them sorted", paths)
	}
}

func TestProcessLayer_DirectoryWhiteout(t *testing.T) {
	t.Parallel()

	merged := make(map[string]*image.FileMeasurement)
	lower := createTarLayer(t, []tarEntry{
		{name: "opt/app/bin", mode: 0o755, typeflag: tar.TypeReg, body: []byte("bin")},
		{name: "opt/app/lib/x.so", mode: 0o644, typeflag: tar.TypeReg, body: []byte("lib")},
		{name: "opt/application", mode: 0o644, typeflag: tar.TypeReg, body: []byte("sibling")},
	})
	upper := createTarLayer(t, []tarEntry{
		{name: "opt/.wh.app", mode: 0o644, typeflag: tar.TypeReg},
	})

	for i, layer := range []v1.Layer{lower, upper} {
		rc, err := layer.Uncompressed()
		if err != nil {
			t.Fatalf("open layer %d: %v", i, err)
		}
		if err = image.ProcessLayer(rc, "layer", merged); err != nil {
			t.Fatalf("process layer %d: %v", i, err)
		}
		_ = rc.Close()
	}

	// the whole /opt/app tree is deleted, but not its sibling sharing the prefix.
	if len(merged) != 1 {
		t.Fatalf("got %d files, want only /opt/application", len(merged))
	}
	if _, ok := merged["/opt/application"]; !ok {
		t.Fatal("/opt/application was deleted")
	}
}
