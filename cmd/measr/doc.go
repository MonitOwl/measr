// Command measr prints the reference values of a container image: the digests
// of every regular file of its merged filesystem.
//
//	measr [-json] [-insecure-registries host:port,...] <image-reference>
//
// With -json it prints the [image.MeasuredImage]: the reference, the digest it
// resolves to and the measurements of the files, which can be decoded back with
// [encoding/json.Unmarshal].
package main
