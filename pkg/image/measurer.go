package image

import (
	"archive/tar"
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"

	//nolint: gosec // sha1 is a valid PCR hash algo so we need to support it for attestation purposes.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// supportedHashAlgos lists the hash algorithms supported for file measurements.
// These algorithms are used to compute digests of file contents in container images.
var supportedHashAlgos = []crypto.Hash{
	crypto.SHA1,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

// GetSupportedHashAlgos returns the list of supported hash algorithms for file measurements.
func GetSupportedHashAlgos() []crypto.Hash {
	return slices.Clone(supportedHashAlgos)
}

// HashAlgoToString converts a [crypto.Hash] to its string representation.
func HashAlgoToString(algo crypto.Hash) (string, error) {
	if !slices.Contains(supportedHashAlgos, algo) {
		return "", fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
	return algo.String(), nil
}

// Measurer computes file digests from container images pulled from a registry.
type Measurer struct {
	options []remote.Option // auth, transport, platform, etc.
}

// NewMeasurer creates a new Measurer with the given remote options.
func NewMeasurer(opts ...remote.Option) *Measurer {
	return &Measurer{options: opts}
}

// MeasureImage pulls the image identified by ref and returns measurements
// for every regular file in the merged filesystem.
//
// ref can be a tag ("ubuntu:22.04") or a digest ("ubuntu@sha256:abc...").
// remote.Option controls authentication, platform, and transport.
func (m *Measurer) MeasureImage(ref string) ([]*FileMeasurement, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}

	img, err := remote.Image(parsed, m.options...)
	if err != nil {
		return nil, fmt.Errorf("pull image %q: %w", ref, err)
	}

	return MeasureParsedImage(img)
}

// MeasureImageFromDigest pulls an image by its registry host, repository
// and exact digest — the preferred form for attestation since digests
// are immutable.
func (m *Measurer) MeasureImageFromDigest(registry, repository, digest string) ([]*FileMeasurement, error) {
	ref, err := name.NewDigest(fmt.Sprintf("%s/%s@%s", registry, repository, digest))
	if err != nil {
		return nil, fmt.Errorf("parse digest ref: %w", err)
	}

	img, err := remote.Image(ref, m.options...)
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", ref, err)
	}

	return MeasureParsedImage(img)
}

// MeasureParsedImage walks all layers of a v1.Image and produces the merged
// filesystem measurements. Exported so callers with an already-fetched
// v1.Image (e.g. from a local daemon, tarball, or mock in tests) can use it directly.
func MeasureParsedImage(img v1.Image) ([]*FileMeasurement, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("get layers: %w", err)
	}

	// merged filesystem: path → measurement, upper layers overwrite lower
	merged := make(map[string]*FileMeasurement)

	for _, layer := range layers {
		digest, layerErr := layer.Digest()
		if layerErr != nil {
			return nil, fmt.Errorf("layer digest: %w", layerErr)
		}

		// Uncompressed() returns a tar stream of the layer contents.
		// go-containerregistry handles decompression transparently.
		rc, openErr := layer.Uncompressed()
		if openErr != nil {
			return nil, fmt.Errorf("open layer %s: %w", digest, openErr)
		}

		procErr := processLayer(rc, digest.String(), merged)
		closeErr := rc.Close()
		if procErr != nil {
			if closeErr != nil {
				return nil, fmt.Errorf("process layer %s: %w; close: %w", digest, procErr, closeErr)
			}
			return nil, fmt.Errorf("process layer %s: %w", digest, procErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close layer %s: %w", digest, closeErr)
		}
	}

	measurements := make([]*FileMeasurement, 0, len(merged))
	for _, m := range merged {
		measurements = append(measurements, m)
	}
	return measurements, nil
}

// processLayer reads a single layer tar stream and measures all the regular files within it.
func processLayer(r io.Reader, layerDigest string, merged map[string]*FileMeasurement) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		path := normalizePath(hdr.Name)

		// Opaque whiteout files delete all files in a directory from the merged filesystem.
		if isOpaqueWhiteout(hdr.Name) {
			dir := path[:strings.LastIndex(path, "/"+opaqueWhiteoutMarker)]
			for k := range merged {
				if strings.HasPrefix(k, dir+"/") {
					delete(merged, k)
				}
			}
			continue
		}

		// Whiteout files delete the file they point to from the merged filesystem.
		if isWhiteout(hdr.Name) {
			delete(merged, whiteoutOriginal(hdr.Name))
			continue
		}

		// Only regular files are measured.
		// Directories, symlinks, and other special files are ignored.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		digests, err := hashEntry(tr)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}

		merged[path] = &FileMeasurement{
			path:        path,
			mode:        hdr.Mode,
			layerDigest: layerDigest,
			digests:     digests,
		}
	}
	return nil
}

// hashEntry computes the digests of a tar entry using all supported hash algorithms.
// It returns a map from [crypto.Hash] to the raw digest bytes.
func hashEntry(r io.Reader) (map[crypto.Hash][]byte, error) {
	type hasher struct {
		algo crypto.Hash
		h    hash.Hash
	}

	hashers := make([]hasher, len(supportedHashAlgos))
	writers := make([]io.Writer, len(supportedHashAlgos))

	for i, algo := range supportedHashAlgos {
		h := algo.New()
		hashers[i] = hasher{algo, h}
		writers[i] = h
	}

	if _, err := io.Copy(io.MultiWriter(writers...), r); err != nil {
		return nil, err
	}

	digests := make(map[crypto.Hash][]byte, len(supportedHashAlgos))
	for _, h := range hashers {
		digests[h.algo] = h.h.Sum(nil)
	}
	return digests, nil
}
