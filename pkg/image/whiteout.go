package image

import (
	"path"
	"strings"
)

const (
	// whiteoutPrefix marks the files deleted by a layer.
	whiteoutPrefix = ".wh."
	// opaqueWhiteoutMarker marks the directories whose lower content is replaced by a layer.
	opaqueWhiteoutMarker = ".wh..wh..opq"
)

// normalizePath converts a tar entry name to a clean absolute path.
func normalizePath(name string) string {
	return path.Clean("/" + strings.TrimPrefix(name, "./"))
}

// isWhiteout reports whether the tar entry deletes a file of the lower layers.
func isWhiteout(name string) bool {
	base := path.Base(name)
	return strings.HasPrefix(base, whiteoutPrefix) && base != opaqueWhiteoutMarker
}

// isOpaqueWhiteout reports whether the tar entry replaces the content of its
// directory in the lower layers.
func isOpaqueWhiteout(name string) bool {
	return path.Base(name) == opaqueWhiteoutMarker
}

// whiteoutOriginal returns the path of the file deleted by a whiteout entry.
func whiteoutOriginal(name string) string {
	dir, base := path.Split(name)
	return normalizePath(dir + strings.TrimPrefix(base, whiteoutPrefix))
}
