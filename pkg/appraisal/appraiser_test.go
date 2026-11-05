package appraisal_test

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/MonitOwl/measr/pkg/appraisal"
	"github.com/MonitOwl/measr/pkg/image"
)

const (
	testImage      = "sha256:1111"
	unmeasuredImg  = "sha256:2222"
	testBashDigest = "aa01"
	testLsDigest   = "bb02"
)

// countingImages serves reference values from memory and counts image lookups.
type countingImages struct {
	images  appraisal.Images
	lookups int
}

func (c *countingImages) ImageFiles(ctx context.Context, digest string) ([]*image.FileMeasurement, error) {
	c.lookups++
	return c.images.ImageFiles(ctx, digest)
}

// reference returns the measurement of the file at path with the given hex digest.
func reference(t *testing.T, path string, algo crypto.Hash, digest string) *image.FileMeasurement {
	t.Helper()
	b, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:exhaustive // a reference value of a single algorithm.
	m, err := image.NewFileMeasurement(path, 0o755, "sha256:layer", map[crypto.Hash][]byte{algo: b})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newTestAppraiser(t *testing.T) (*appraisal.Appraiser, *countingImages) {
	t.Helper()
	rv := &countingImages{images: appraisal.Images{
		testImage: {
			reference(t, "/usr/bin/bash", crypto.SHA256, testBashDigest),
			reference(t, "/usr/bin/ls", crypto.SHA256, testLsDigest),
			// a reference value of another algorithm never matches.
			reference(t, "/usr/bin/cat", crypto.SHA512, "cc"),
		},
	}}
	return appraisal.New(rv, crypto.SHA256), rv
}

// file returns the runtime measurement of the file at path with the given digest.
func file(path, digest string) appraisal.Measurement {
	return appraisal.Measurement{Path: path, Digest: digest}
}

// strict returns a policy requiring reference values for every measured file.
func strict(name string, allowedPaths ...string) appraisal.Policy {
	return appraisal.Policy{
		Name:                   name,
		RequireMeasuredImage:   true,
		RequireReferenceValues: true,
		AllowedPaths:           allowedPaths,
	}
}

func TestAppraise(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		image      string
		files      []appraisal.Measurement
		policy     appraisal.Policy
		violations int
	}{
		{
			name:   "all files match reference values",
			image:  testImage,
			files:  []appraisal.Measurement{file("/usr/bin/bash", testBashDigest), file("/usr/bin/ls", testLsDigest)},
			policy: strict("p"),
		},
		{
			name:   "digests are case insensitive",
			image:  testImage,
			files:  []appraisal.Measurement{file("/usr/bin/bash", strings.ToUpper(testBashDigest))},
			policy: strict("p"),
		},
		{
			name:       "tampered file",
			image:      testImage,
			files:      []appraisal.Measurement{file("/usr/bin/bash", "dead")},
			policy:     strict("p"),
			violations: 1,
		},
		{
			name:       "unknown file",
			image:      testImage,
			files:      []appraisal.Measurement{file("/tmp/payload", "beef")},
			policy:     strict("p"),
			violations: 1,
		},
		{
			name:   "unknown file in allowed subtree",
			image:  testImage,
			files:  []appraisal.Measurement{file("/tmp/a/payload", "beef")},
			policy: strict("p", "/tmp/**"),
		},
		{
			name:   "unknown file matching allowed glob",
			image:  testImage,
			files:  []appraisal.Measurement{file("/opt/app.py", "beef")},
			policy: strict("p", "/opt/*.py"),
		},
		{
			name:       "reference value of another algorithm",
			image:      testImage,
			files:      []appraisal.Measurement{file("/usr/bin/cat", "cc")},
			policy:     strict("p"),
			violations: 1,
		},
		{
			name:       "unmeasured image",
			image:      unmeasuredImg,
			files:      []appraisal.Measurement{file("/usr/bin/bash", testBashDigest)},
			policy:     strict("p"),
			violations: 1,
		},
		{
			name:   "unmeasured image allowed",
			image:  unmeasuredImg,
			files:  []appraisal.Measurement{file("/usr/bin/bash", testBashDigest)},
			policy: appraisal.Policy{Name: "p"},
		},
		{
			name:   "reference values not required",
			image:  testImage,
			files:  []appraisal.Measurement{file("/tmp/payload", "beef")},
			policy: appraisal.Policy{Name: "p", RequireMeasuredImage: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, _ := newTestAppraiser(t)

			res, err := a.Appraise(context.Background(), tt.image, tt.files, []appraisal.Policy{tt.policy})
			if err != nil {
				t.Fatalf("Appraise: %v", err)
			}
			if len(res.Violations) != tt.violations || res.Passed() != (tt.violations == 0) {
				t.Fatalf("got violations %v, want %d", res.Violations, tt.violations)
			}
		})
	}
}

func TestAppraiseAppliesEveryPolicy(t *testing.T) {
	t.Parallel()
	a, _ := newTestAppraiser(t)

	policies := []appraisal.Policy{strict("lenient", "/tmp/**"), strict("strict")}
	files := []appraisal.Measurement{file("/tmp/x", "beef")}
	res, err := a.Appraise(context.Background(), testImage, files, policies)
	if err != nil {
		t.Fatalf("Appraise: %v", err)
	}
	if len(res.Violations) != 1 || !strings.Contains(res.Violations[0], "policy strict") {
		t.Fatalf("got violations %v, want one from policy strict", res.Violations)
	}
	if res.ViolatingFiles != 1 {
		t.Fatalf("got %d violating files, want 1", res.ViolatingFiles)
	}
}

func TestAppraiseCachesMeasuredImages(t *testing.T) {
	t.Parallel()
	a, rv := newTestAppraiser(t)
	policies := []appraisal.Policy{strict("p")}

	for range 3 {
		for _, digest := range []string{testImage, unmeasuredImg} {
			if _, err := a.Appraise(context.Background(), digest, nil, policies); err != nil {
				t.Fatalf("Appraise: %v", err)
			}
		}
	}
	// the measured image is looked up once, the unmeasured image every time.
	if rv.lookups != 4 {
		t.Fatalf("got %d lookups, want 4", rv.lookups)
	}
}

func TestAppraiseBoundsViolations(t *testing.T) {
	t.Parallel()
	a, _ := newTestAppraiser(t)

	var files []appraisal.Measurement
	for i := range appraisal.MaxViolations + 5 {
		files = append(files, file("/bin/f"+strconv.Itoa(i), "beef"))
	}
	res, err := a.Appraise(context.Background(), testImage, files, []appraisal.Policy{strict("p")})
	if err != nil {
		t.Fatalf("Appraise: %v", err)
	}
	if len(res.Violations) != appraisal.MaxViolations+1 || res.Violations[appraisal.MaxViolations] != "... and 5 more" {
		t.Fatalf("got %d violations, last %q", len(res.Violations), res.Violations[len(res.Violations)-1])
	}
	if res.MeasuredFiles != appraisal.MaxViolations+5 {
		t.Fatalf("got %d measured files", res.MeasuredFiles)
	}
	// the count is exact, unlike the truncated list.
	if res.ViolatingFiles != appraisal.MaxViolations+5 {
		t.Fatalf("got %d violating files, want %d", res.ViolatingFiles, appraisal.MaxViolations+5)
	}
}

// failingImages fails every lookup.
type failingImages struct{}

var errLookup = errors.New("lookup failed")

func (failingImages) ImageFiles(context.Context, string) ([]*image.FileMeasurement, error) {
	return nil, errLookup
}

func TestAppraiseReferenceValuesFailure(t *testing.T) {
	t.Parallel()

	a := appraisal.New(failingImages{}, crypto.SHA256)
	_, err := a.Appraise(context.Background(), testImage, nil, []appraisal.Policy{strict("p")})
	if !errors.Is(err, errLookup) {
		t.Fatalf("got error %v, want %v", err, errLookup)
	}
}

func TestImages(t *testing.T) {
	t.Parallel()

	images := appraisal.Images{testImage: {reference(t, "/usr/bin/bash", crypto.SHA256, testBashDigest)}}
	files, err := images.ImageFiles(context.Background(), testImage)
	if err != nil || len(files) != 1 {
		t.Fatalf("ImageFiles = %v, %v, want one file", files, err)
	}
	if _, err = images.ImageFiles(context.Background(), unmeasuredImg); !errors.Is(err, appraisal.ErrImageNotMeasured) {
		t.Fatalf("got error %v, want %v", err, appraisal.ErrImageNotMeasured)
	}
}
