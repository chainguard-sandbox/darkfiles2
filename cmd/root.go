package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "darkfiles",
	Short: "Find files in container images not tracked by any package manager or SBOM",
	Long: `darkfiles analyzes container images and identifies "dark" files — files that
exist in the image but are not referenced by any package manager database or
attached SBOM. These files represent an unknown surface area that security
scanners may miss.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
