package image

import (
	"archive/tar"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
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

// MeasuredImage is the measurement of an image pulled from a registry.
type MeasuredImage struct {
	// Reference is the reference the image was pulled with.
	Reference string `json:"reference"`
	// Digest is the digest the reference resolves to in the registry: of the
	// image index for a multi-platform image, else of the manifest. Container
	// runtimes report it as the repository digest of the image a container
	// runs, e.g. in the image ID of a Kubernetes container status.
	Digest string `json:"digest"`
	// Files are the measurements of the files of the image, sorted by path.
	Files []*FileMeasurement `json:"files"`
}

// MeasureImage pulls the image with the given reference, a tag like "ubuntu:24.04"
// or a digest like "ubuntu@sha256:...", and measures its files. An image index
// is resolved to the image of the platform set with [remote.WithPlatform],
// linux/amd64 by default.
func (m *Measurer) MeasureImage(ctx context.Context, ref string) (*MeasuredImage, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	desc, err := remote.Get(parsed, append(slices.Clone(m.options), remote.WithContext(ctx))...)
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", ref, err)
	}
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", ref, err)
	}
	files, err := Measure(img)
	if err != nil {
		return nil, err
	}
	return &MeasuredImage{Reference: ref, Digest: desc.Digest.String(), Files: files}, nil
}

const (
	// maxLinkHops bounds the symlinks followed to resolve a path, as the
	// kernel does, so that symlink loops do not resolve.
	maxLinkHops = 40
	// maxAliasRounds bounds the expansions of the directory symlinks, so that
	// symlinks to an ancestor directory do not expand forever.
	maxAliasRounds = 8
)

// filesystem is the merged filesystem of the layers of an image.
type filesystem struct {
	// files maps the paths of the regular files to their measurement:
	// upper layers override lower ones.
	files map[string]*FileMeasurement
	// symlinks maps the paths of the symbolic links to their target.
	symlinks map[string]string
}

func newFilesystem() *filesystem {
	return &filesystem{files: make(map[string]*FileMeasurement), symlinks: make(map[string]string)}
}

// Measure measures the regular files of the merged filesystem of img, sorted
// by path. It serves images obtained otherwise than from a registry, e.g.
// from a tarball.
//
// The files reached through symbolic links are also measured at the path of
// the link, e.g. /usr/bin/find for a link to /bin/busybox, or /bin/bash when
// /bin links to /usr/bin: runtime measurements record the path an executable
// was invoked with.
func Measure(img v1.Image) ([]*FileMeasurement, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("get layers: %w", err)
	}

	fs := newFilesystem()
	for _, layer := range layers {
		if err = measureLayer(layer, fs); err != nil {
			return nil, err
		}
	}
	fs.addLinkAliases()

	return slices.SortedFunc(maps.Values(fs.files), func(a, b *FileMeasurement) int {
		return cmp.Compare(a.path, b.path)
	}), nil
}

// measureLayer applies the layer to the merged filesystem.
func measureLayer(layer v1.Layer, fs *filesystem) error {
	digest, err := layer.Digest()
	if err != nil {
		return fmt.Errorf("get layer digest: %w", err)
	}
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("open layer %s: %w", digest, err)
	}
	err = processLayer(rc, digest.String(), fs)
	if err = errors.Join(err, rc.Close()); err != nil {
		return fmt.Errorf("layer %s: %w", digest, err)
	}
	return nil
}

// processLayer applies the tar stream of a layer to the merged filesystem:
// whiteouts delete the files of lower layers, regular files and hard links are
// measured, and symbolic links are recorded.
func processLayer(r io.Reader, layerDigest string, fs *filesystem) error {
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
			fs.deleteTree(normalizePath(hdr.Name[:len(hdr.Name)-len(opaqueWhiteoutMarker)]), false)
		case isWhiteout(hdr.Name):
			// the file or directory is deleted.
			fs.deleteTree(whiteoutOriginal(hdr.Name), true)
		case hdr.Typeflag == tar.TypeReg:
			p := normalizePath(hdr.Name)
			digests, hashErr := hashFile(tr)
			if hashErr != nil {
				return fmt.Errorf("hash %s: %w", p, hashErr)
			}
			delete(fs.symlinks, p)
			fs.files[p] = &FileMeasurement{
				path:        p,
				mode:        hdr.Mode,
				layerDigest: layerDigest,
				digests:     digests,
			}
		case hdr.Typeflag == tar.TypeLink:
			// a hard link is the file it links to, archived earlier.
			p := normalizePath(hdr.Name)
			delete(fs.symlinks, p)
			delete(fs.files, p)
			if target, ok := fs.files[normalizePath(hdr.Linkname)]; ok {
				fs.files[p] = target.at(p)
			}
		case hdr.Typeflag == tar.TypeSymlink:
			p := normalizePath(hdr.Name)
			delete(fs.files, p)
			fs.symlinks[p] = hdr.Linkname
		default:
			// directories and special files are not measured.
		}
	}
}

// deleteTree deletes the files and links under dir from the merged
// filesystem, and dir itself if self is set.
func (fs *filesystem) deleteTree(dir string, self bool) {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	inTree := func(p string) bool { return (self && p == dir) || strings.HasPrefix(p, prefix) }
	maps.DeleteFunc(fs.files, func(p string, _ *FileMeasurement) bool { return inTree(p) })
	maps.DeleteFunc(fs.symlinks, func(p string, _ string) bool { return inTree(p) })
}

// resolve returns the path that p designates, following the symbolic links of
// each of its components within the image, or false if they loop.
func (fs *filesystem) resolve(p string) (string, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	resolved := "/"
	for hops := 0; len(parts) > 0; {
		next := path.Join(resolved, parts[0])
		parts = parts[1:]
		target, isLink := fs.symlinks[next]
		if !isLink {
			resolved = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return "", false
		}
		// a relative target is relative to the directory of the link; the
		// remaining components are resolved from the target.
		if !path.IsAbs(target) {
			target = path.Join(resolved, target)
		}
		parts = append(strings.Split(strings.Trim(path.Clean(target), "/"), "/"), parts...)
		resolved = "/"
	}
	return resolved, true
}

// addLinkAliases measures the files reached through symbolic links at the
// paths of the links: the links to files, then the files under the links to
// directories, until no path is added. The links to a directory containing
// them, e.g. to ".", are not expanded: they only add the same files at
// longer paths.
func (fs *filesystem) addLinkAliases() {
	for range maxAliasRounds {
		// the aliases of a round are added at its end, so that a round
		// expands each link once.
		aliases := make(map[string]*FileMeasurement)
		for link := range fs.symlinks {
			fs.linkAliases(link, aliases)
		}
		if len(aliases) == 0 {
			return
		}
		maps.Copy(fs.files, aliases)
	}
}

// linkAliases adds to aliases the files reached through the link, at its path,
// that are not measured yet.
func (fs *filesystem) linkAliases(link string, aliases map[string]*FileMeasurement) {
	alias := func(p string, file *FileMeasurement) {
		if _, exists := fs.files[p]; !exists {
			aliases[p] = file.at(p)
		}
	}

	target, ok := fs.resolve(link)
	if !ok {
		return
	}
	if file, isFile := fs.files[target]; isFile {
		alias(link, file)
		return
	}
	// the link designates a directory: alias the files under it.
	prefix := strings.TrimSuffix(target, "/") + "/"
	if strings.HasPrefix(link+"/", prefix) {
		return
	}
	for p, file := range fs.files {
		if strings.HasPrefix(p, prefix) {
			alias(path.Join(link, p[len(prefix):]), file)
		}
	}
}
