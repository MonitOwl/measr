# measr

[![Go Reference](https://pkg.go.dev/badge/github.com/MonitOwl/measr.svg)](https://pkg.go.dev/github.com/MonitOwl/measr/pkg/image)

Go library that measures the files of container images, producing the reference values that
runtime file measurements are compared to.

## Overview

Integrity monitors such as [anchr](https://github.com/MonitOwl/anchr) measure the files executed
or loaded inside containers at runtime. To appraise those measurements, a verifier needs to know
the digests the files are expected to have. measr computes them from the image itself: it pulls
an image, rebuilds its merged filesystem layer by layer, and hashes every regular file. It then
appraises the files measured in a running container against the reference values of its image.

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
  be measured directly, e.g. one loaded from a tarball. Private registries are accessed with the
  credentials of the default keychain, and insecure ones over plain HTTP.
- **JSON reference values.** Measurements encode to and decode from JSON, so reference values
  can be stored and loaded back.
- **Appraisal.** The files measured at runtime are checked against the reference values of the
  image, under policies that can require a measured image, require every file to match, and
  allow paths without a reference value.
- **CLI.** `measr` prints the reference values of an image, as text or JSON.

Directories and special files (devices, FIFOs, sockets) are not measured.

## Directory Structure

```
measr/
├── cmd/
│   └── measr/             # CLI printing the reference values of an image
├── pkg/
│   ├── appraisal/         # Appraisal of runtime measurements against reference values
│   ├── image/             # Container image measurement
│   └── registry/          # Registry access options (keychain, insecure registries)
├── go.mod                 # Go module
├── .golangci.yml          # Linter configuration
└── LICENSE                # Apache License 2.0
```

## Installation

Requirements: Go 1.26.5+

```bash
go get github.com/MonitOwl/measr

# CLI
go install github.com/MonitOwl/measr/cmd/measr@latest
```

## Usage

### Command line

```bash
# Path, mode, layer and digests of every file
measr ubuntu:24.04

# JSON reference values: the reference, the digest it resolves to and the measurements
measr -json ubuntu:24.04 > refvalues.json

# Registries accessed over plain HTTP
measr -insecure-registries localhost:5000 localhost:5000/app:1.0
```

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
	measured, err := measurer.MeasureImage(context.Background(), "ubuntu:24.04")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(measured.Digest) // the digest container runtimes report for the image
	for _, m := range measured.Files {
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

`MeasuredImage.Digest` is the digest the reference resolves to: of the image index for a
multi-platform image, else of the manifest. It is the repository digest container runtimes report
for the image a container runs, e.g. in the `imageID` of a Kubernetes container status, so it
keys the reference values of the image. An index is measured for the platform set with
`remote.WithPlatform`, linux/amd64 by default.

`registry.Options` returns the options the CLI uses: the credentials of the default keychain,
and plain HTTP for the listed insecure registries:

```go
measurer := image.NewMeasurer(registry.Options([]string{"localhost:5000"})...)
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

`MeasureImage` and `Measure` measure the files sorted by path. Each `FileMeasurement`
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

A `FileMeasurement` encodes to JSON as an object with its path, its mode in octal, its layer
digest and its hex-encoded digests by algorithm name, and decodes back with validation:

```json
{"path": "/usr/bin/bash", "mode": "0755", "layer_digest": "sha256:...", "digests": {"SHA-256": "..."}}
```

```go
// e.g. the output of measr -json
var measured image.MeasuredImage
if err := json.Unmarshal(raw, &measured); err != nil {
	log.Fatal(err)
}
```

### Appraise a container

The `appraisal` package compares the files measured at runtime in a container, e.g. by
[anchr](https://github.com/MonitOwl/anchr), with the reference values of the image the container
runs. The runtime measurements must have been verified first, e.g. by replaying the container's
measurement list up to a TPM quote: appraisal only decides whether the verified files are the
expected ones.

```go
// Reference values by image digest; implement appraisal.ReferenceValues to load them elsewhere
appraiser := appraisal.New(appraisal.Images{measured.Digest: measured.Files}, crypto.SHA256)

files := []appraisal.Measurement{
	{Path: "/usr/bin/bash", Digest: "<hex-encoded SHA-256>"},
}
// imageDigest is the digest the container runtime reports for the image of the container
res, err := appraiser.Appraise(ctx, imageDigest, files, []appraisal.Policy{{
	Name:                   "strict",
	RequireMeasuredImage:   true,
	RequireReferenceValues: true,
	AllowedPaths:           []string{"/tmp/**"},
}})
if err != nil {
	log.Fatal(err) // the appraisal could not be performed
}
if !res.Passed() {
	fmt.Println(res.ViolatingFiles, "files failed appraisal:", res.Violations)
}
```

A file passes when its path and digest match a reference value of the image, or when its path
matches one of `AllowedPaths` ([`path.Match`](https://pkg.go.dev/path#Match) syntax, with a
trailing `/**` matching a whole subtree). Violations are capped at `appraisal.MaxViolations` per
container; `ViolatingFiles` is not.

## Development

```bash
# Run the tests
go test ./...

# Run the linter
golangci-lint run
```

# License

This project is open-source software distributed under the terms of the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.
