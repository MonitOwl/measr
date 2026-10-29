package appraisal

import (
	"path"
	"strings"
)

// subtreeWildcard is the pattern suffix matching a whole directory subtree.
const subtreeWildcard = "/**"

// Policy holds the appraisal rules of an attestation policy.
type Policy struct {
	// Name identifies the policy in violation messages.
	Name string
	// RequireMeasuredImage requires the image to have reference values.
	RequireMeasuredImage bool
	// RequireReferenceValues requires every measured file to match a reference
	// value of the image, unless allowed by AllowedPaths.
	RequireReferenceValues bool
	// AllowedPaths are glob patterns of files allowed without a reference value.
	// Patterns follow [path.Match] syntax; a trailing "/**" matches a whole subtree.
	AllowedPaths []string
}

// pathAllowed reports whether filePath matches any of the given patterns.
// Patterns follow [path.Match] syntax; a trailing "/**" matches a whole subtree.
// Malformed patterns never match.
func pathAllowed(patterns []string, filePath string) bool {
	for _, pattern := range patterns {
		if dir, ok := strings.CutSuffix(pattern, subtreeWildcard); ok {
			if strings.HasPrefix(filePath, dir+"/") {
				return true
			}
			continue
		}
		if ok, err := path.Match(pattern, filePath); err == nil && ok {
			return true
		}
	}
	return false
}
