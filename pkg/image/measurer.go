package image

import (
	"archive/tar"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Measurer measures images pulled from a registry.
type Measurer struct {
	options []remote.Option
}

// NewMeasurer creates a Measurer pulling images with the given options,
// e.g. for authentication or transport.
func NewMeasurer(opts ...remote.Option) *Measurer {
	return &Measurer{options: opts}
}

// MeasureImage pulls the image with the given reference, a tag like "ubuntu:24.04"
// or a digest like "ubuntu@sha256:...", and measures its files.
func (m *Measurer) MeasureImage(ctx context.Context, ref string) ([]*FileMeasurement, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	img, err := remote.Image(parsed, append(slices.Clone(m.options), remote.WithContext(ctx))...)
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", ref, err)
	}
	return Measure(img)
}

// Measure measures the regular files of the merged filesystem of img, sorted
// by path. It serves images obtained otherwise than from a registry, e.g.
// from a tarball.
func Measure(img v1.Image) ([]*FileMeasurement, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("get layers: %w", err)
	}

	// merged maps the paths of the merged filesystem to their measurement:
	// upper layers override lower ones.
	merged := make(map[string]*FileMeasurement)
	for _, layer := range layers {
		if err = measureLayer(layer, merged); err != nil {
			return nil, err
		}
	}

	return slices.SortedFunc(maps.Values(merged), func(a, b *FileMeasurement) int {
		return cmp.Compare(a.path, b.path)
	}), nil
}

// measureLayer applies the layer to the merged filesystem.
func measureLayer(layer v1.Layer, merged map[string]*FileMeasurement) error {
	digest, err := layer.Digest()
	if err != nil {
		return fmt.Errorf("get layer digest: %w", err)
	}
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("open layer %s: %w", digest, err)
	}
	err = processLayer(rc, digest.String(), merged)
	if err = errors.Join(err, rc.Close()); err != nil {
		return fmt.Errorf("layer %s: %w", digest, err)
	}
	return nil
}

// processLayer applies the tar stream of a layer to the merged filesystem:
// whiteouts delete the files of lower layers, and regular files are measured.
func processLayer(r io.Reader, layerDigest string, merged map[string]*FileMeasurement) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		switch {
		case isOpaqueWhiteout(hdr.Name):
			// the directory content of the lower layers is replaced.
			deleteTree(merged, normalizePath(hdr.Name[:len(hdr.Name)-len(opaqueWhiteoutMarker)]), false)
		case isWhiteout(hdr.Name):
			// the file or directory is deleted.
			deleteTree(merged, whiteoutOriginal(hdr.Name), true)
		case hdr.Typeflag == tar.TypeReg:
			path := normalizePath(hdr.Name)
			digests, hashErr := hashFile(tr)
			if hashErr != nil {
				return fmt.Errorf("hash %s: %w", path, hashErr)
			}
			merged[path] = &FileMeasurement{
				path:        path,
				mode:        hdr.Mode,
				layerDigest: layerDigest,
				digests:     digests,
			}
		default:
			// directories, links and special files are not measured.
		}
	}
}

// deleteTree deletes the files under dir from the merged filesystem, and dir
// itself if self is set.
func deleteTree(merged map[string]*FileMeasurement, dir string, self bool) {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for path := range merged {
		if (self && path == dir) || strings.HasPrefix(path, prefix) {
			delete(merged, path)
		}
	}
}
