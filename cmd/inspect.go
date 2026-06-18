package cmd

import (
	"strings"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/chainguard-dev/darkfiles2/internal/image"
	"github.com/chainguard-dev/darkfiles2/internal/report"
	"github.com/spf13/cobra"
)

var inspectFlags struct {
	all bool
	tar string
}

var inspectCmd = &cobra.Command{
	Use:   "inspect <image>",
	Short: "Deep-dive into dark files: show layer origin and file metadata",
	Long: `inspect shows each dark file grouped by the layer (Dockerfile instruction)
that introduced it, along with file size and permissions.

By default only CategoryUnknown files are shown. Use --all to include
expected files (package manager state, device files, etc.).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ref, imgFS, err := loadFS(args, inspectFlags.tar)
		if err != nil {
			return err
		}

		r, _, warnErr := analyzeImage(ref, imgFS)
		if warnErr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", warnErr)
		}

		candidates := r.DarkFiles
		if !inspectFlags.all {
			candidates = r.UnknownFiles()
		}

		if len(candidates) == 0 {
			fmt.Println("No dark files found.")
			return nil
		}

		// Group by layer index.
		byLayer := map[int][]report.CategorizedFile{}
		for _, f := range candidates {
			byLayer[f.LayerIndex] = append(byLayer[f.LayerIndex], f)
		}

		// Sort layer indices for deterministic output.
		layerIdxs := make([]int, 0, len(byLayer))
		for idx := range byLayer {
			layerIdxs = append(layerIdxs, idx)
		}
		sort.Ints(layerIdxs)

		for _, lIdx := range layerIdxs {
			files := byLayer[lIdx]

			// Print layer header.
			var cmd string
			var diffID string
			if lIdx < len(imgFS.Layers) {
				l := imgFS.Layers[lIdx]
				cmd = l.Command()
				diffID = shortDigest(l.DiffID)
			} else {
				cmd = fmt.Sprintf("layer %d", lIdx)
			}

			fmt.Printf("\n┌─ Layer %d", lIdx)
			if diffID != "" {
				fmt.Printf(" [%s]", diffID)
			}
			fmt.Println()
			fmt.Printf("│  %s\n", cmd)
			fmt.Printf("│  %d dark file(s)\n", len(files))
			fmt.Println("│")

			// Sort files within the layer.
			sort.Slice(files, func(i, j int) bool {
				return files[i].Path < files[j].Path
			})

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for _, f := range files {
				prefix := "├──"
				mode := formatMode(f.File)
				cat := ""
				if inspectFlags.all && f.Cat != report.CategoryUnknown {
					cat = fmt.Sprintf("  [%s]", f.Cat)
				}
				fmt.Fprintf(tw, "│  %s %s\t%s\t%s%s\n",
					prefix, f.Path, humanSize(f.Size), mode, cat)
			}
			tw.Flush()
			fmt.Println("└" + strings.Repeat("─", 60))
		}
		return nil
	},
}

func init() {
	inspectCmd.Flags().BoolVar(&inspectFlags.all, "all", false, "Include expected dark files (pkg manager state, /dev, etc.), not just unknown")
	inspectCmd.Flags().StringVar(&inspectFlags.tar, "tar", "", "Load image from local OCI tar file instead of a registry")
	rootCmd.AddCommand(inspectCmd)
}

func shortDigest(d string) string {
	// "sha256:abcdef..." -> "abcdef" (12 chars)
	s := d
	if idx := len("sha256:"); len(s) > idx {
		s = s[idx:]
	}
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

func formatMode(f image.File) string {
	m := fs.FileMode(f.Mode)
	if f.IsSymlink {
		return fmt.Sprintf("-> %s", f.LinkTarget)
	}
	return m.String()
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
