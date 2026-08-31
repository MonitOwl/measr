package image

// Export internal functions for testing from package image_test.
var (
	NormalizePath    = normalizePath
	IsWhiteout       = isWhiteout
	IsOpaqueWhiteout = isOpaqueWhiteout
	WhiteoutOriginal = whiteoutOriginal
	HashEntry        = hashEntry
	ProcessLayer     = processLayer
)
