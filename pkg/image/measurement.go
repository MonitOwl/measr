package image

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"slices"
)

// FileMeasurement records the identity and digests of a single regular file
// extracted from a container image layer. It contains exactly what is needed
// to attest the file at runtime: its path, permissions, and cryptographic
// digests computed at image build time as golden reference values.
type FileMeasurement struct {
	// path is the absolute file path within the container rootfs,
	// e.g. "/usr/bin/bash". This is what the runtime verifier matches against.
	path string

	// mode is the file permission bits. Useful for detecting permission
	// tampering in addition to content tampering.
	mode int64

	// digests maps each supported hash algorithm to the raw digest bytes
	// of the file content. All entries are populated in a single IO pass.
	digests map[crypto.Hash][]byte

	// layerDigest is the digest of the image layer this file originates from.
	// Useful for tracing which layer introduced or last modified this file.
	layerDigest string
}

// NewFileMeasurement creates a new FileMeasurement instance with the given parameters.
func NewFileMeasurement(
	path string,
	mode int64,
	layerDigest string,
	digests map[crypto.Hash][]byte,
) (*FileMeasurement, error) {
	// digests must be supported
	for algo := range digests {
		if !slices.Contains(supportedHashAlgos, algo) {
			return nil, fmt.Errorf("unsupported hash algorithm: %v", algo)
		}
	}

	return &FileMeasurement{
		path:        path,
		mode:        mode,
		layerDigest: layerDigest,
		digests:     digests,
	}, nil
}

func (m *FileMeasurement) Path() string {
	return m.path
}

func (m *FileMeasurement) Mode() int64 {
	return m.mode
}

func (m *FileMeasurement) LayerDigest() string {
	return m.layerDigest
}

func (m *FileMeasurement) Digests() map[crypto.Hash][]byte {
	return m.digests
}

func (m *FileMeasurement) PrintableDigests() map[string]string {
	printable := make(map[string]string)
	for algo, digest := range m.digests {
		printable[algo.String()] = hex.EncodeToString(digest)
	}
	return printable
}

// Digest returns the raw digest bytes for the given algorithm.
func (m *FileMeasurement) Digest(algo crypto.Hash) ([]byte, bool) {
	d, ok := m.digests[algo]
	return d, ok
}

// HexDigest returns the hex-encoded digest for the given algorithm.
func (m *FileMeasurement) HexDigest(algo crypto.Hash) (string, bool) {
	d, ok := m.digests[algo]
	if !ok {
		return "", false
	}
	return hex.EncodeToString(d), true
}
