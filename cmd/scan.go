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

		r, _, warnErr := analyzeImage(ref, fs)
		if warnErr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", warnErr)
		}

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

// analyzeImage runs the package-db scan and dark-file analysis under a spinner,
// since both can be slow on large images. The returned warnErr is non-fatal (a
// failed pkgdb scan) and should be surfaced but not abort the command.
func analyzeImage(ref string, fs *image.ImageFS) (r *report.Result, tracked map[string]struct{}, warnErr error) {
	_ = withSpinner("Analyzing files", func() error {
		var distro string
		tracked, distro, warnErr = pkgdb.TrackedFiles(fs)
		r = report.Analyze(ref, distro, fs, tracked)
		return nil
	})
	return r, tracked, warnErr
}

func loadFS(args []string, tarPath string) (string, *image.ImageFS, error) {
	if tarPath != "" {
		var fs *image.ImageFS
		err := withSpinner(fmt.Sprintf("Loading image from %s", tarPath), func() error {
			var e error
			fs, e = image.LoadFromTar(tarPath)
			return e
		})
		if err != nil {
			return "", nil, err
		}
		return tarPath, fs, nil
	}
	if len(args) == 0 {
		return "", nil, fmt.Errorf("an image reference is required (or use --tar)")
	}
	ref := args[0]
	var fs *image.ImageFS
	err := withSpinner(fmt.Sprintf("Pulling and extracting %s", ref), func() error {
		var e error
		fs, e = image.Load(ref)
		return e
	})
	if err != nil {
		return "", nil, err
	}
	return ref, fs, nil
}
