package cmd

import (
	"fmt"
	"os"

	"github.com/chainguard-dev/darkfiles2/internal/image"
	"github.com/chainguard-dev/darkfiles2/internal/pkgdb"
	"github.com/chainguard-dev/darkfiles2/internal/report"
	"github.com/spf13/cobra"
)

var scanFlags struct {
	format string
	tar    string
}

var scanCmd = &cobra.Command{
	Use:   "scan <image>",
	Short: "Scan an image and report dark file statistics",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref, fs, err := loadFS(args, scanFlags.tar)
		if err != nil {
			return err
		}

		tracked, distro, err := pkgdb.TrackedFiles(fs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}

		r := report.Analyze(ref, distro, fs, tracked)

		switch scanFlags.format {
		case "json":
			return report.PrintJSON(os.Stdout, r)
		default:
			report.PrintStats(os.Stdout, r)
		}
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanFlags.format, "format", "text", "Output format: text or json")
	scanCmd.Flags().StringVar(&scanFlags.tar, "tar", "", "Load image from local OCI tar file instead of a registry")
}

func loadFS(args []string, tarPath string) (string, *image.ImageFS, error) {
	if tarPath != "" {
		fs, err := image.LoadFromTar(tarPath)
		if err != nil {
			return "", nil, err
		}
		return tarPath, fs, nil
	}
	if len(args) == 0 {
		return "", nil, fmt.Errorf("an image reference is required (or use --tar)")
	}
	ref := args[0]
	fs, err := image.Load(ref)
	if err != nil {
		return "", nil, err
	}
	return ref, fs, nil
}
