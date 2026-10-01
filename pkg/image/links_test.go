package image_test

import (
	"archive/tar"
	"crypto"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/MonitOwl/measr/pkg/image"
)

// measureLayers measures an image of the given layers, by path.
func measureLayers(t *testing.T, layers ...[]tarEntry) map[string]*image.FileMeasurement {
	t.Helper()
	img := empty.Image
	for _, entries := range layers {
		var err error
		if img, err = mutate.AppendLayers(img, createTarLayer(t, entries)); err != nil {
			t.Fatalf("AppendLayers: %v", err)
		}
	}
	measurements, err := image.Measure(img)
	if err != nil {
		t.Fatalf("Measure: %v", err)
	}
	byPath := make(map[string]*image.FileMeasurement, len(measurements))
	for _, m := range measurements {
		byPath[m.Path()] = m
	}
	return byPath
}

// sameFile reports whether the measurements at a and b are of the same content.
func sameFile(byPath map[string]*image.FileMeasurement, a, b string) bool {
	ma, okA := byPath[a]
	mb, okB := byPath[b]
	if !okA || !okB {
		return false
	}
	da, _ := ma.HexDigest(crypto.SHA256)
	db, _ := mb.HexDigest(crypto.SHA256)
	return da == db
}

func reg(name, body string) tarEntry {
	return tarEntry{name: name, mode: 0o755, typeflag: tar.TypeReg, body: []byte(body)}
}

func symlink(name, target string) tarEntry {
	return tarEntry{name: name, mode: 0o777, typeflag: tar.TypeSymlink, linkname: target}
}

func TestMeasureFileSymlinks(t *testing.T) {
	t.Parallel()

	// the layout of the BusyBox applets of Alpine.
	byPath := measureLayers(t, []tarEntry{
		reg("bin/busybox", "busybox"),
		symlink("bin/sh", "/bin/busybox"),
		symlink("usr/bin/find", "/bin/busybox"),
		symlink("usr/bin/sort", "../../bin/busybox"),
		symlink("usr/bin/chain", "sort"),
		symlink("usr/bin/dangling", "/missing"),
	})

	for _, link := range []string{"/bin/sh", "/usr/bin/find", "/usr/bin/sort", "/usr/bin/chain"} {
		if !sameFile(byPath, link, "/bin/busybox") {
			t.Errorf("%s: not measured as /bin/busybox", link)
		}
	}
	if _, ok := byPath["/usr/bin/dangling"]; ok {
		t.Error("/usr/bin/dangling: measured, but its target does not exist")
	}
	if got := len(byPath); got != 5 {
		t.Errorf("got %d measurements, want 5", got)
	}
}

func TestMeasureDirectorySymlinks(t *testing.T) {
	t.Parallel()

	// the merged /usr of Debian: /bin links to usr/bin, /usr/bin/sh to dash.
	byPath := measureLayers(t, []tarEntry{
		reg("usr/bin/bash", "bash"),
		reg("usr/bin/dash", "dash"),
		symlink("usr/bin/sh", "dash"),
		symlink("bin", "usr/bin"),
		reg("usr/lib/x86_64-linux-gnu/libc.so.6", "libc"),
		symlink("lib", "usr/lib"),
		symlink("lib64", "/usr/lib"),
	})

	for link, file := range map[string]string{
		"/bin/bash":                         "/usr/bin/bash",
		"/bin/sh":                           "/usr/bin/dash",
		"/usr/bin/sh":                       "/usr/bin/dash",
		"/lib/x86_64-linux-gnu/libc.so.6":   "/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/x86_64-linux-gnu/libc.so.6": "/usr/lib/x86_64-linux-gnu/libc.so.6",
	} {
		if !sameFile(byPath, link, file) {
			t.Errorf("%s: not measured as %s", link, file)
		}
	}
}

func TestMeasureSymlinkLoops(t *testing.T) {
	t.Parallel()

	byPath := measureLayers(t, []tarEntry{
		reg("bin/tool", "tool"),
		symlink("loop/a", "b"),
		symlink("loop/b", "a"),
		// a link to its own directory is not expanded.
		symlink("bin/self", "."),
	})

	for p := range byPath {
		if len(p) > 64 {
			t.Errorf("unbounded alias %s", p)
		}
	}
	if _, ok := byPath["/loop/a"]; ok {
		t.Error("/loop/a: measured, but its links loop")
	}
	if _, ok := byPath["/bin/self/tool"]; ok {
		t.Error("/bin/self/tool: measured, but /bin/self links to its own directory")
	}
}

func TestMeasureLinksAcrossLayers(t *testing.T) {
	t.Parallel()

	byPath := measureLayers(t,
		[]tarEntry{
			reg("bin/busybox", "busybox"),
			reg("bin/old", "old"),
			symlink("bin/grep", "busybox"),
			symlink("bin/gone", "busybox"),
			{name: "bin/hard", mode: 0o755, typeflag: tar.TypeLink, linkname: "bin/old"},
		},
		[]tarEntry{
			// the link is deleted, the file at the path of another link replaces it.
			reg("bin/.wh.gone", ""),
			reg("bin/grep", "gnu grep"),
		},
	)

	if _, ok := byPath["/bin/gone"]; ok {
		t.Error("/bin/gone: measured, but deleted by a whiteout")
	}
	if sameFile(byPath, "/bin/grep", "/bin/busybox") {
		t.Error("/bin/grep: measured as the link of the lower layer, not as the file replacing it")
	}
	if !sameFile(byPath, "/bin/hard", "/bin/old") {
		t.Error("/bin/hard: hard link not measured as /bin/old")
	}
}
