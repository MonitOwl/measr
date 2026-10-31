// Package image measures the files of container images.
//
// A [Measurer] pulls an image and hashes every regular file of its merged
// filesystem, i.e. after applying the OCI whiteouts of every layer. The
// resulting [FileMeasurement]s are the reference values the files of running
// containers are compared to.
//
// # Measuring an image
//
// [Measurer.MeasureImage] pulls an image from a registry by tag or digest:
//
//	measurer := image.NewMeasurer(remote.WithAuthFromKeychain(authn.DefaultKeychain))
//	measured, err := measurer.MeasureImage(ctx, "ubuntu:24.04")
//
// The [MeasuredImage] holds the digest the reference resolves to, of the image
// index for a multi-platform image: container runtimes report that digest for
// the image a container runs, so it keys the reference values of the image.
//
// [Measure] measures any [v1.Image], e.g. one loaded from a tarball:
//
//	img, err := tarball.ImageFromPath("image.tar", nil)
//	if err != nil {
//		return err
//	}
//	measurements, err := image.Measure(img)
//
// Both measure the files sorted by path.
//
// # Merged filesystem
//
// Layers are applied in order, as a container runtime does: upper layers
// override lower ones, and whiteouts (.wh.<name>) and opaque whiteouts
// (.wh..wh..opq) delete the files of lower layers. A hard link is measured as
// the file it links to.
//
// Runtime measurements record the path a file was invoked with, so the files
// reached through symbolic links are also measured at the path of the link,
// e.g. /usr/bin/find for a link to /bin/busybox, or /bin/bash when /bin links
// to /usr/bin. Links are resolved within the image, and symlink loops are
// bounded as in the kernel.
//
// Directories and special files (devices, FIFOs, sockets) are not measured.
//
// # Digests
//
// Every file is hashed with each of [SupportedHashAlgos] (SHA-1, SHA-256,
// SHA-384 and SHA-512) in a single read, so that the measurements match any
// TPM PCR bank. [FileMeasurement.Digest] and [FileMeasurement.HexDigest]
// return the digest for one algorithm.
//
// Measurements built elsewhere, e.g. loaded from a reference value database,
// can be created with [NewFileMeasurement].
package image
