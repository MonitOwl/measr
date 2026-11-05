package appraisal

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/MonitOwl/measr/pkg/image"
)

// defaultMaxCachedImages bounds the number of image reference sets kept in memory.
const defaultMaxCachedImages = 64

// ErrImageNotMeasured is returned by a [ReferenceValues] for an image without reference values.
var ErrImageNotMeasured = errors.New("image not measured")

// Measurement is a file measured at runtime within a container.
type Measurement struct {
	// Path is the path the file was measured at, e.g. "/usr/bin/bash".
	Path string
	// Digest is the hex-encoded digest of the file content.
	Digest string
}

// Result is the outcome of the appraisal of a container.
type Result struct {
	// MeasuredFiles is the number of files measured in the container.
	MeasuredFiles int
	// ViolatingFiles is the number of distinct measured files that failed
	// appraisal against any policy. Unlike Violations, it is not truncated.
	ViolatingFiles int
	// Violations lists the reasons the container failed appraisal, if any.
	Violations []string
}

// Passed reports whether the container satisfies every policy.
func (r *Result) Passed() bool {
	return len(r.Violations) == 0
}

// ReferenceValues provides the reference values of measured images.
type ReferenceValues interface {
	// ImageFiles returns the measurements of the files of the image with the
	// given digest, or an error wrapping [ErrImageNotMeasured] if it has none.
	ImageFiles(ctx context.Context, digest string) ([]*image.FileMeasurement, error)
}

// Images is an in-memory [ReferenceValues], mapping image digests to the
// measurements of their files.
type Images map[string][]*image.FileMeasurement

// ImageFiles returns the measurements of the image with the given digest.
func (i Images) ImageFiles(_ context.Context, digest string) ([]*image.FileMeasurement, error) {
	files, ok := i[digest]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrImageNotMeasured, digest)
	}
	return files, nil
}

// referenceSet is the set of reference values of an image, keyed by [referenceKey].
type referenceSet map[string]struct{}

func referenceKey(filePath, hexDigest string) string {
	return filePath + "\x00" + strings.ToLower(hexDigest)
}

// Appraiser appraises container measurements. It is safe for concurrent use.
type Appraiser struct {
	rv       ReferenceValues
	hashAlgo crypto.Hash

	mu        sync.RWMutex
	cache     map[string]referenceSet
	maxCached int
}

// New creates an Appraiser comparing measurements taken with hashAlgo, one of
// [image.SupportedHashAlgos], to the reference values provided by rv.
func New(rv ReferenceValues, hashAlgo crypto.Hash) *Appraiser {
	return &Appraiser{
		rv:        rv,
		hashAlgo:  hashAlgo,
		cache:     make(map[string]referenceSet),
		maxCached: defaultMaxCachedImages,
	}
}

// Appraise evaluates the files measured in a container running the image with
// the given digest against every policy. The integrity of the measurements must
// have been verified. An error means the appraisal could not be performed.
func (a *Appraiser) Appraise(
	ctx context.Context,
	imageDigest string,
	files []Measurement,
	policies []Policy,
) (*Result, error) {
	refs, measured, err := a.referenceSet(ctx, imageDigest)
	if err != nil {
		return nil, err
	}

	var v violations
	violating := make(map[Measurement]struct{})
	for i := range policies {
		p := &policies[i]
		switch {
		case !measured:
			if p.RequireMeasuredImage || p.RequireReferenceValues {
				v.addf("policy %s: image %s has no reference values", p.Name, imageDigest)
			}
		case p.RequireReferenceValues:
			for _, f := range files {
				if _, ok := refs[referenceKey(f.Path, f.Digest)]; ok || pathAllowed(p.AllowedPaths, f.Path) {
					continue
				}
				v.addf("policy %s: unexpected measurement %s (%s)", p.Name, f.Path, strings.ToLower(f.Digest))
				violating[Measurement{Path: f.Path, Digest: strings.ToLower(f.Digest)}] = struct{}{}
			}
		}
	}

	return &Result{MeasuredFiles: len(files), ViolatingFiles: len(violating), Violations: v.list()}, nil
}

// referenceSet returns the reference values of the image with the given digest,
// and whether the image was measured at all. Images are immutable, so the
// reference values of measured images are cached.
func (a *Appraiser) referenceSet(ctx context.Context, imageDigest string) (referenceSet, bool, error) {
	a.mu.RLock()
	refs, ok := a.cache[imageDigest]
	a.mu.RUnlock()
	if ok {
		return refs, true, nil
	}

	files, err := a.rv.ImageFiles(ctx, imageDigest)
	if errors.Is(err, ErrImageNotMeasured) {
		// not cached: the image may be measured later.
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get reference values of image %s: %w", imageDigest, err)
	}

	refs = make(referenceSet, len(files))
	for _, f := range files {
		if digest, found := f.HexDigest(a.hashAlgo); found {
			refs[referenceKey(f.Path(), digest)] = struct{}{}
		}
	}

	a.mu.Lock()
	if len(a.cache) >= a.maxCached {
		clear(a.cache)
	}
	a.cache[imageDigest] = refs
	a.mu.Unlock()

	return refs, true, nil
}
