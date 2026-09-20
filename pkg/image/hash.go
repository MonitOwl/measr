package image

import (
	"crypto"
	"hash"
	"io"
	"slices"

	//nolint:gosec // SHA-1 is a TPM PCR bank algorithm, so it must be supported.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// supportedHashAlgos are the algorithms every file is hashed with, in a single read.
var supportedHashAlgos = []crypto.Hash{
	crypto.SHA1,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

// SupportedHashAlgos returns the algorithms file digests are computed with.
func SupportedHashAlgos() []crypto.Hash {
	return slices.Clone(supportedHashAlgos)
}

// hashFile returns the digests of the content read from r with every supported algorithm.
func hashFile(r io.Reader) (map[crypto.Hash][]byte, error) {
	hashes := make([]hash.Hash, len(supportedHashAlgos))
	writers := make([]io.Writer, len(supportedHashAlgos))
	for i, algo := range supportedHashAlgos {
		hashes[i] = algo.New()
		writers[i] = hashes[i]
	}

	if _, err := io.Copy(io.MultiWriter(writers...), r); err != nil {
		return nil, err
	}

	digests := make(map[crypto.Hash][]byte, len(supportedHashAlgos))
	for i, algo := range supportedHashAlgos {
		digests[algo] = hashes[i].Sum(nil)
	}
	return digests, nil
}
