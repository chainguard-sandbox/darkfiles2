package cmd

import (
	"fmt"
	"os"

	"github.com/chainguard-dev/darkfiles2/internal/report"
	"github.com/spf13/cobra"
)

var listFlags struct {
	set      string
	detailed bool
	group    bool
	tar      string
}

var listCmd = &cobra.Command{
	Use:   "list <image>",
	Short: "List files from an image, optionally filtered and grouped by category",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref, fs, err := loadFS(args, listFlags.tar)
		if err != nil {
			return err
		}

		r, tracked, warnErr := analyzeImage(ref, fs)
		if warnErr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", warnErr)
		}

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
		case "unknown":
			// Show only CategoryUnknown — files that genuinely warrant investigation.
			sub := &report.Result{
				ImageRef:  r.ImageRef,
				Distro:    r.Distro,
				DarkFiles: r.UnknownFiles(),
			}
			if listFlags.detailed {
				report.PrintDarkFilesDetailed(os.Stdout, sub, listFlags.group)
			} else {
				report.PrintDarkFiles(os.Stdout, sub, listFlags.group)
			}
		default: // "dark"
			if listFlags.detailed {
				report.PrintDarkFilesDetailed(os.Stdout, r, listFlags.group)
			} else {
				report.PrintDarkFiles(os.Stdout, r, listFlags.group)
			}
		}
		return nil
	},
}

func init() {
	listCmd.Flags().StringVar(&listFlags.set, "set", "dark",
		"Which files to list: dark, unknown (unrecognised dark only), tracked, or all")
	listCmd.Flags().BoolVar(&listFlags.detailed, "detailed", false, "Show file sizes alongside paths")
	listCmd.Flags().BoolVar(&listFlags.group, "group", false, "Group output by category")
	listCmd.Flags().StringVar(&listFlags.tar, "tar", "", "Load image from local OCI tar file instead of a registry")
}
