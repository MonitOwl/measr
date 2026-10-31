package image_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/MonitOwl/measr/pkg/image"
)

func TestFileMeasurementJSON(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("content"))
	//nolint:exhaustive // a measurement may hold a subset of the algorithms.
	original, err := image.NewFileMeasurement("/usr/bin/bash", 0o755, "sha256:1234",
		map[crypto.Hash][]byte{crypto.SHA256: digest[:]})
	if err != nil {
		t.Fatalf("NewFileMeasurement: %v", err)
	}

	data, err := json.Marshal([]*image.FileMeasurement{original})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `[{"path":"/usr/bin/bash","mode":"0755","layer_digest":"sha256:1234",` +
		`"digests":{"SHA-256":"ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73"}}]`
	if string(data) != want {
		t.Fatalf("Marshal = %s, want %s", data, want)
	}

	var decoded []*image.FileMeasurement
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(decoded) != 1 || !reflect.DeepEqual(decoded[0], original) {
		t.Fatalf("Unmarshal = %+v, want %+v", decoded, original)
	}
}

func TestFileMeasurementUnmarshalJSONFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"not an object":         `[]`,
		"invalid mode":          `{"path":"/a","mode":"rwx","digests":{"SHA-256":"00"}}`,
		"unsupported algorithm": `{"path":"/a","mode":"0644","digests":{"MD5":"00"}}`,
		"invalid digest":        `{"path":"/a","mode":"0644","digests":{"SHA-256":"zz"}}`,
		"empty path":            `{"path":"","mode":"0644","digests":{"SHA-256":"00"}}`,
		"no digests":            `{"path":"/a","mode":"0644","digests":{}}`,
	}
	for name, data := range tests {
		var m image.FileMeasurement
		if err := json.Unmarshal([]byte(data), &m); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
