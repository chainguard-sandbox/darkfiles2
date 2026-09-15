package cmd

import (
	"fmt"
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
The attestation's cosign signature is verified against Docker's published
DHI key (override with --sbom-key); if it cannot be verified the SBOM is
not applied unless --insecure-sbom is given.

The --set flag selects which files the --detailed, --paths, and --detect-libs
views operate on:
  unknown  unrecognised dark files (default)
  dark     all dark files, including expected ones (pkg state, /dev, etc.)
  tracked  files owned by a package
  all      every file in the image
  in-sbom  files accounted for by the SBOM (requires --sbom)

Add --detect-libs to scan the selected files for statically-linked libraries and
their versions, using string-signature heuristics ported from cve-bin-tool. This
is useful for spotting libraries vendored into binaries that no package manager
tracks. It is off by default; combine with --code to restrict detection to
executables and libraries. Because it honours --set, it is not limited to dark
files — use --set tracked or --set all to also scan package-owned binaries and
libraries (e.g. darkfiles --detect-libs --code --set all <image>).`,
	Args:         cobra.MaximumNArgs(1),
	RunE:         runScan,
	SilenceUsage: true,
}

// SetVersionInfo wires build metadata into the --version output. The values
// are injected at build time by GoReleaser via -ldflags -X main.{version,commit,date}.
func SetVersionInfo(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
