package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pterm/pterm"

	"github.com/MonitOwl/measr/pkg/image"
	"github.com/MonitOwl/measr/pkg/registry"
)

func parseInsecureRegistries(raw string) []string {
	var insecure []string
	for host := range strings.SplitSeq(raw, ",") {
		if h := strings.TrimSpace(host); h != "" {
			insecure = append(insecure, h)
		}
	}
	return insecure
}

func outputJSON(measured *image.MeasuredImage) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(measured)
}

func outputFormatted(measured *image.MeasuredImage) {
	fmt.Fprintf(os.Stdout, "%s (digest: %s)\n\n", measured.Reference, measured.Digest)
	for _, m := range measured.Files {
		fmt.Fprintf(os.Stdout, "%s (mode: %04o, layer: %s)\n", m.Path(), m.Mode(), m.LayerDigest())
		for algo, digest := range m.PrintableDigests() {
			fmt.Fprintf(os.Stdout, "  %-10s %s\n", algo, digest)
		}
	}
	fmt.Fprintf(os.Stdout, "\nTotal files measured: %d\n", len(measured.Files))
}

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	insecureFlag := fs.String(
		"insecure-registries",
		"",
		"Comma-separated list of insecure registries (plain HTTP)",
	)
	jsonFlag := fs.Bool("json", false, "Output results as JSON")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <image-reference>\n\nFlags:\n", os.Args[0])
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	imageRef := fs.Arg(0)
	insecure := parseInsecureRegistries(*insecureFlag)

	measurer := image.NewMeasurer(registry.Options(insecure)...)
	sp, _ := pterm.DefaultSpinner.WithWriter(os.Stderr).Start("Measuring " + imageRef)
	measured, err := measurer.MeasureImage(context.Background(), imageRef)
	if err != nil {
		sp.Fail("Measuring " + imageRef)
		fmt.Fprintf(os.Stderr, "Error measuring image %q: %v\n", imageRef, err)
		os.Exit(1)
	}

	sp.Success(fmt.Sprintf("Measured %s (%d files)", imageRef, len(measured.Files)))

	if *jsonFlag {
		if jsonErr := outputJSON(measured); jsonErr != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", jsonErr)
			os.Exit(1)
		}
		return
	}

	outputFormatted(measured)
}
