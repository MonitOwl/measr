// Package appraisal evaluates the files measured at runtime within containers
// against the reference values of their images, i.e. the [image.FileMeasurement]s
// of the image files.
//
// The runtime measurements must have been verified first, e.g. by replaying
// the measurement list of the container up to a TPM quote: appraisal only
// decides whether the verified files are the expected ones. A file passes when
// its path and digest match a reference value of the image, or when a policy
// allows its path without one.
//
//	appraiser := appraisal.New(appraisal.Images{"sha256:...": measurements}, crypto.SHA256)
//	res, err := appraiser.Appraise(ctx, "sha256:...", files, []appraisal.Policy{{
//		Name:                   "strict",
//		RequireMeasuredImage:   true,
//		RequireReferenceValues: true,
//		AllowedPaths:           []string{"/tmp/**"},
//	}})
package appraisal
