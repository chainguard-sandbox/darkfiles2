package cmd

import (
	"fmt"
	"os"

	"github.com/chainguard-dev/darkfiles2/internal/pkgdb"
	"github.com/chainguard-dev/darkfiles2/internal/report"
	"github.com/spf13/cobra"
)

var listFlags struct {
	set      string
	detailed bool
	tar      string
}

var listCmd = &cobra.Command{
	Use:   "list <image>",
	Short: "List files from an image, optionally filtered by tracking status",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref, fs, err := loadFS(args, listFlags.tar)
		if err != nil {
			return err
		}

		tracked, distro, err := pkgdb.TrackedFiles(fs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}

		r := report.Analyze(ref, distro, fs, tracked)

		switch listFlags.set {
		case "all":
			for _, f := range fs.Files {
				fmt.Fprintln(os.Stdout, f.Path)
			}
		case "tracked":
			for _, f := range fs.Files {
				if _, ok := tracked[f.Path]; ok {
					fmt.Fprintln(os.Stdout, f.Path)
				}
			}
		default: // "dark"
			if listFlags.detailed {
				report.PrintDarkFilesDetailed(os.Stdout, r)
			} else {
				report.PrintDarkFiles(os.Stdout, r)
			}
		}
		return nil
	},
}

func init() {
	listCmd.Flags().StringVar(&listFlags.set, "set", "dark", "Which files to list: dark, tracked, or all")
	listCmd.Flags().BoolVar(&listFlags.detailed, "detailed", false, "Show file sizes alongside paths")
	listCmd.Flags().StringVar(&listFlags.tar, "tar", "", "Load image from local OCI tar file instead of a registry")
}
