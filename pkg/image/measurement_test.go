package image_test

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/MonitOwl/measr/pkg/image"
)

func TestNewFileMeasurement(t *testing.T) {
	t.Parallel()

	//nolint:exhaustive
	validDigests := map[crypto.Hash][]byte{
		crypto.SHA256: []byte("sha256-test-digest-bytes-32byte!"),
		crypto.SHA512: []byte("sha512-test-digest-bytes-64bytes-long-digest-for-testing-purpose!"),
	}

	tests := []struct {
		name        string
		path        string
		mode        int64
		layerDigest string
		digests     map[crypto.Hash][]byte
		wantErr     bool
	}{
		{
			name:        "valid file measurement",
			path:        "/usr/bin/bash",
			mode:        0o755,
			layerDigest: "sha256:1234567890abcdef",
			digests:     validDigests,
			wantErr:     false,
		},
		{
			name:        "empty path",
			path:        "",
			mode:        0o644,
			layerDigest: "sha256:1234567890abcdef",
			digests:     validDigests,
			wantErr:     true,
		},
		{
			name:        "empty digests",
			path:        "/etc/passwd",
			mode:        0o644,
			layerDigest: "sha256:1234567890abcdef",
			digests:     nil,
			wantErr:     true,
		},
		{
			name:        "unsupported hash algorithm",
			path:        "/bin/ls",
			mode:        0o755,
			layerDigest: "sha256:1234567890abcdef",
			//nolint:exhaustive
			digests: map[crypto.Hash][]byte{
				crypto.MD5: []byte("md5-is-not-supported"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := image.NewFileMeasurement(tt.path, tt.mode, tt.layerDigest, tt.digests)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewFileMeasurement() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if m.Path() != tt.path {
					t.Errorf("Path() = %v, want %v", m.Path(), tt.path)
				}
				if m.Mode() != tt.mode {
					t.Errorf("Mode() = %v, want %v", m.Mode(), tt.mode)
				}
				if m.LayerDigest() != tt.layerDigest {
					t.Errorf("LayerDigest() = %v, want %v", m.LayerDigest(), tt.layerDigest)
				}
			}
		})
	}
}

func TestFileMeasurement_DigestsAndHex(t *testing.T) {
	t.Parallel()

	rawSHA256 := []byte("sha256-test-bytes-abcdef12345678")
	rawSHA1 := []byte("sha1-test-bytes-1234")
	//nolint:exhaustive
	digests := map[crypto.Hash][]byte{
		crypto.SHA256: rawSHA256,
		crypto.SHA1:   rawSHA1,
	}

	m, err := image.NewFileMeasurement("/app/server", 0o755, "sha256:layer123", digests)
	if err != nil {
		t.Fatalf("unexpected error creating measurement: %v", err)
	}

	// Verify Digests map
	allDigests := m.Digests()
	if len(allDigests) != 2 {
		t.Errorf("expected 2 digests, got %d", len(allDigests))
	}

	// Verify defensive copy of Digests map
	allDigests[crypto.SHA512] = []byte("mutated")
	if _, exists := m.Digests()[crypto.SHA512]; exists {
		t.Errorf("Digests() did not return a defensive copy")
	}

	// Test Digest retrieval
	d, ok := m.Digest(crypto.SHA256)
	if !ok {
		t.Fatal("expected SHA256 digest to be found")
	}
	if string(d) != string(rawSHA256) {
		t.Errorf("got %s, want %s", string(d), string(rawSHA256))
	}

	// Test Digest defensive copy
	d[0] = 'X'
	d2, _ := m.Digest(crypto.SHA256)
	if d2[0] == 'X' {
		t.Errorf("Digest() did not return a defensive slice copy")
	}

	// Test not found algorithm
	if _, found := m.Digest(crypto.SHA384); found {
		t.Errorf("expected SHA384 digest to not be found")
	}

	// Test HexDigest
	hex256, okHex := m.HexDigest(crypto.SHA256)
	if !okHex {
		t.Fatal("expected SHA256 hex digest to be found")
	}
	if hex256 != hex.EncodeToString(rawSHA256) {
		t.Errorf("HexDigest() = %v, want %v", hex256, hex.EncodeToString(rawSHA256))
	}

	if _, foundHex := m.HexDigest(crypto.SHA384); foundHex {
		t.Errorf("expected SHA384 hex digest to not be found")
	}

	// Test PrintableDigests
	printable := m.PrintableDigests()
	if printable["SHA-256"] != hex.EncodeToString(rawSHA256) {
		t.Errorf("PrintableDigests()[SHA-256] = %v, want %v", printable["SHA-256"], hex.EncodeToString(rawSHA256))
	}
	if printable["SHA-1"] != hex.EncodeToString(rawSHA1) {
		t.Errorf("PrintableDigests()[SHA-1] = %v, want %v", printable["SHA-1"], hex.EncodeToString(rawSHA1))
	}
}
