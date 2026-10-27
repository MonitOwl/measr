# measr

[![Go Reference](https://pkg.go.dev/badge/github.com/MonitOwl/measr.svg)](https://pkg.go.dev/github.com/MonitOwl/measr/pkg/image)

Go library that measures the files of container images, producing the reference values that
runtime file measurements are compared to.

## Overview

Integrity monitors such as [anchr](https://github.com/MonitOwl/anchr) measure the files executed
or loaded inside containers at runtime. To appraise those measurements, a verifier needs to know
the digests the files are expected to have. measr computes them from the image itself: it pulls
an image, rebuilds its merged filesystem layer by layer, and hashes every regular file.

For every file it records:

- **Path** - the absolute path within the container filesystem, e.g. `/usr/bin/bash`
- **Mode** - the permission bits, to detect permission tampering as well as content tampering
- **Digests** - SHA-1, SHA-256, SHA-384 and SHA-512 of the content, computed in a single read so
  that the measurements match any TPM PCR bank
- **Layer digest** - the image layer that introduced or last modified the file

## Features

- **Merged filesystem.** Layers are applied in order, as a container runtime does: upper layers
  override lower ones, and OCI whiteouts (`.wh.<name>`) and opaque whiteouts (`.wh..wh..opq`)
  delete the files of lower layers.
- **Hard links.** A hard link is measured as the file it links to.
- **Symbolic links.** Runtime measurements record the path a file was invoked with, so the files
  reached through symbolic links are also measured at the path of the link, e.g. `/usr/bin/find`
  for a link to `/bin/busybox`, or `/bin/bash` when `/bin` links to `/usr/bin`. Links are
  resolved within the image, with relative and absolute targets, and symlink loops are bounded
  as in the kernel.
- **Any image source.** Images are pulled from a registry with
  [go-containerregistry](https://github.com/google/go-containerregistry), or any `v1.Image` can
  be measured directly, e.g. one loaded from a tarball.

Directories and special files (devices, FIFOs, sockets) are not measured.

## Directory Structure

```
measr/
├── pkg/
│   └── image/             # Container image measurement
├── go.mod                 # Go module
└── .golangci.yml          # Linter configuration
```

## Installation

Requirements: Go 1.26.5+

```bash
go get github.com/MonitOwl/measr
```

## Usage

### Measure an image from a registry

```go
package main

import (
	"context"
	"crypto"
	"fmt"
	"log"

	"github.com/MonitOwl/measr/pkg/image"
)

func main() {
	measurer := image.NewMeasurer()

	// A tag like "ubuntu:24.04" or a digest like "ubuntu@sha256:..."
	measurements, err := measurer.MeasureImage(context.Background(), "ubuntu:24.04")
	if err != nil {
		log.Fatal(err)
	}

	for _, m := range measurements {
		digest, _ := m.HexDigest(crypto.SHA256)
		fmt.Printf("%s %04o %s\n", digest, m.Mode(), m.Path())
	}
}
```

`NewMeasurer` accepts go-containerregistry
[`remote.Option`](https://pkg.go.dev/github.com/google/go-containerregistry/pkg/v1/remote#Option)s,
e.g. for registry authentication or a custom transport:

```go
measurer := image.NewMeasurer(remote.WithAuthFromKeychain(authn.DefaultKeychain))
```

### Measure an image from another source

```go
img, err := tarball.ImageFromPath("image.tar", nil)
if err != nil {
	log.Fatal(err)
}
measurements, err := image.Measure(img)
```

### Reading measurements

`MeasureImage` and `Measure` return the measurements sorted by path. Each `FileMeasurement`
exposes:

| Method | Returns |
| --- | --- |
| `Path()` | Absolute path within the container filesystem |
| `Mode()` | Permission bits |
| `LayerDigest()` | Digest of the layer the file comes from |
| `Digest(algo)` | Raw digest for a hash algorithm |
| `HexDigest(algo)` | Hex-encoded digest for a hash algorithm |
| `Digests()` | Copy of all raw digests, by algorithm |
| `PrintableDigests()` | All hex-encoded digests, by algorithm name |

`image.SupportedHashAlgos()` lists the algorithms digests are computed with. Measurements built
elsewhere, e.g. loaded from a reference value database, can be created with
`image.NewFileMeasurement`.

The full API reference, with runnable examples, is on
[pkg.go.dev](https://pkg.go.dev/github.com/MonitOwl/measr/pkg/image). To browse it locally:

```bash
go doc -all ./pkg/image
# or, as rendered by pkg.go.dev
go run golang.org/x/pkgsite/cmd/pkgsite@latest   # then open http://localhost:8080/github.com/MonitOwl/measr
```

## Development

```bash
# Run the tests
go test ./...

# Run the linter
golangci-lint run
```
