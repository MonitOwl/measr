package image_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/MonitOwl/measr/pkg/image"
)

//nolint:testableexamples // pulls an image from a registry.
func ExampleMeasurer_MeasureImage() {
	measurer := image.NewMeasurer(remote.WithAuthFromKeychain(authn.DefaultKeychain))

	// A tag like "ubuntu:24.04" or a digest like "ubuntu@sha256:..."
	measurements, err := measurer.MeasureImage(context.Background(), "ubuntu:24.04")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, m := range measurements {
		digest, _ := m.HexDigest(crypto.SHA256)
		fmt.Printf("%s %04o %s\n", digest, m.Mode(), m.Path())
	}
}

func ExampleMeasure() {
	// A single layer with a binary and a symbolic link to it.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	content := []byte("#!/bin/sh\necho hello\n")
	_ = tw.WriteHeader(&tar.Header{Name: "bin/hello", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))})
	_, _ = tw.Write(content)
	_ = tw.WriteHeader(&tar.Header{Name: "usr/bin/hi", Typeflag: tar.TypeSymlink, Linkname: "/bin/hello"})
	_ = tw.Close()

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		fmt.Println(err)
		return
	}

	measurements, err := image.Measure(img)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, m := range measurements {
		digest, _ := m.HexDigest(crypto.SHA256)
		fmt.Printf("%s %04o %s\n", digest[:16], m.Mode(), m.Path())
	}
	// Output:
	// bfdeaeb08cffb6a3 0755 /bin/hello
	// bfdeaeb08cffb6a3 0755 /usr/bin/hi
}

func ExampleNewFileMeasurement() {
	digest := sha256.Sum256([]byte("#!/bin/sh\necho hello\n"))

	//nolint:exhaustive
	digests := map[crypto.Hash][]byte{
		crypto.SHA256: digest[:],
	}

	m, err := image.NewFileMeasurement("/bin/hello", 0o755, "sha256:...", digests)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(m.PrintableDigests())
	// Output:
	// map[SHA-256:bfdeaeb08cffb6a36438bcd12dda25417e3cdd36f1e7e482a2849d539225288b]
}
