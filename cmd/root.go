package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "darkfiles <image>",
	Short: "Find files in container images not tracked by any package manager",
	Long: `darkfiles analyzes container images and identifies "dark" files — files that
exist in the image but are not referenced by any package manager database.
These files represent an unknown surface area that security scanners may miss.

By default it prints a statistics summary. Add --detailed to also list the
dark files grouped by the layer (Dockerfile instruction) that introduced
them, or --paths to emit a plain list of file paths for scripting.

Add --sbom to cross-reference against the image's SPDX SBOM attestation
(primarily for DHI images). Files the SBOM documents are treated as
accounted-for and excluded from the dark set, reported on their own line.

The --set flag selects which files the --detailed and --paths views operate
on:
  unknown  unrecognised dark files (default)
  dark     all dark files, including expected ones (pkg state, /dev, etc.)
  tracked  files owned by a package
  all      every file in the image
  in-sbom  files accounted for by the SBOM (requires --sbom)`,
	Args:         cobra.MaximumNArgs(1),
	RunE:         runScan,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
