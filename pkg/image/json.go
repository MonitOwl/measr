package image

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// fileMeasurementJSON is the JSON encoding of a [FileMeasurement].
type fileMeasurementJSON struct {
	Path        string            `json:"path"`
	Mode        string            `json:"mode"`
	LayerDigest string            `json:"layer_digest"`
	Digests     map[string]string `json:"digests"`
}

// MarshalJSON encodes the measurement as an object with its path, its mode in
// octal, its layer digest and its hex-encoded digests by algorithm name, e.g.
//
//	{"path": "/usr/bin/bash", "mode": "0755", "layer_digest": "sha256:...", "digests": {"SHA-256": "..."}}
func (m *FileMeasurement) MarshalJSON() ([]byte, error) {
	return json.Marshal(fileMeasurementJSON{
		Path:        m.path,
		Mode:        fmt.Sprintf("%04o", m.mode),
		LayerDigest: m.layerDigest,
		Digests:     m.PrintableDigests(),
	})
}

// UnmarshalJSON decodes a measurement encoded by [FileMeasurement.MarshalJSON],
// validating it as [NewFileMeasurement] does.
func (m *FileMeasurement) UnmarshalJSON(data []byte) error {
	var raw fileMeasurementJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	mode, err := strconv.ParseInt(raw.Mode, 8, 64)
	if err != nil {
		return fmt.Errorf("invalid mode %q: %w", raw.Mode, err)
	}

	digests := make(map[crypto.Hash][]byte, len(raw.Digests))
	for name, hexDigest := range raw.Digests {
		algo, ok := hashAlgoByName(name)
		if !ok {
			return fmt.Errorf("unsupported hash algorithm: %s", name)
		}
		digest, decodeErr := hex.DecodeString(hexDigest)
		if decodeErr != nil {
			return fmt.Errorf("invalid %s digest: %w", name, decodeErr)
		}
		digests[algo] = digest
	}

	decoded, err := NewFileMeasurement(raw.Path, mode, raw.LayerDigest, digests)
	if err != nil {
		return err
	}
	*m = *decoded
	return nil
}

// hashAlgoByName returns the supported hash algorithm with the given name, e.g. "SHA-256".
func hashAlgoByName(name string) (crypto.Hash, bool) {
	for _, algo := range supportedHashAlgos {
		if algo.String() == name {
			return algo, true
		}
	}
	return 0, false
}
