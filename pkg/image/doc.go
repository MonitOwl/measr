// Package image measures the files of container images.
//
// A [Measurer] pulls an image and hashes every regular file of its merged
// filesystem, i.e. after applying the OCI whiteouts of every layer. The
// resulting [FileMeasurement]s are the reference values the files of running
// containers are compared to.
package image
