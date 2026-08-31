package image

import (
	"path"
	"strings"
)

const (
	// whiteoutPrefix is the OCI prefix used to mark deleted files in tar layers.
	whiteoutPrefix = ".wh."

	// opaqueWhiteoutMarker is the OCI entry name indicating an entire directory was replaced.
	opaqueWhiteoutMarker = ".wh..wh..opq"
)

// normalizePath converts a tar entry name to a normalized absolute path.
func normalizePath(name string) string {
	// Clean and ensure leading slash
	return path.Clean("/" + strings.TrimPrefix(name, "./"))
}

// isWhiteout reports whether a tar entry is an OCI whiteout file.
// Whiteout files are used to delete files from the merged filesystem when applying layers.
// Whiteout files have the prefix ".wh." in their base name.
func isWhiteout(name string) bool {
	base := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		base = name[idx+1:]
	}
	return strings.HasPrefix(base, whiteoutPrefix) && base != opaqueWhiteoutMarker
}

// isOpaqueWhiteout reports whether a tar entry is an opaque whiteout,
// which signals that an entire directory was replaced in this layer.
func isOpaqueWhiteout(name string) bool {
	base := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		base = name[idx+1:]
	}
	return base == opaqueWhiteoutMarker
}

// whiteoutOriginal returns the path of the file that a whiteout deletes.
func whiteoutOriginal(name string) string {
	idx := strings.LastIndex(name, "/")
	dir := ""
	base := name
	if idx >= 0 {
		dir = name[:idx+1]
		base = name[idx+1:]
	}
	original := strings.TrimPrefix(base, whiteoutPrefix)
	return normalizePath(dir + original)
}
