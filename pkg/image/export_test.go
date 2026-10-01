package image

import "io"

// Export internal functions for testing from package image_test.
var (
	NormalizePath    = normalizePath
	IsWhiteout       = isWhiteout
	IsOpaqueWhiteout = isOpaqueWhiteout
	WhiteoutOriginal = whiteoutOriginal
	HashFile         = hashFile
)

// ProcessLayer applies a layer to the regular files of merged.
func ProcessLayer(r io.Reader, layerDigest string, merged map[string]*FileMeasurement) error {
	return processLayer(r, layerDigest, &filesystem{files: merged, symlinks: make(map[string]string)})
}
