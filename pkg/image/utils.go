package image

import "strings"

// normalizePath converts a tar entry name to an absolute path.
func normalizePath(name string) string {
	// strip leading "./" from tar entries
	name = strings.TrimPrefix(name, "./")
	// ensure absolute path
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	return name
}

// isWhiteout reports whether a tar entry is an OCI whiteout file.
// Whiteout files are used to delete files from the merged filesystem when applying layers.
// Whiteout files have the prefix ".wh." in their base name.
func isWhiteout(name string) bool {
	base := name[strings.LastIndex(name, "/")+1:]
	return strings.HasPrefix(base, ".wh.") && base != ".wh..wh..opq"
}

// isOpaqueWhiteout reports whether a tar entry is an opaque whiteout,
// which signals that an entire directory was replaced in this layer.
func isOpaqueWhiteout(name string) bool {
	base := name[strings.LastIndex(name, "/")+1:]
	return base == ".wh..wh..opq"
}

// whiteoutOriginal returns the path of the file that a whiteout deletes.
func whiteoutOriginal(name string) string {
	dir := name[:strings.LastIndex(name, "/")+1]
	base := name[strings.LastIndex(name, "/")+1:]
	original := strings.TrimPrefix(base, ".wh.")
	return normalizePath(dir + original)
}
