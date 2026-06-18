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
	format   string
	detailed bool
	paths    bool
	set      string
	group    bool
	sizes    bool
	tar      string
}

var scanCmd = &cobra.Command{
	Use:   "scan <image>",
	Short: "Scan an image and report dark files",
	Long: `scan analyzes a container image for dark files — files not referenced by
any package manager database or attached SBOM.

By default it prints a statistics summary. Add --detailed to also list the
dark files grouped by the layer (Dockerfile instruction) that introduced
them, or --paths to emit a plain list of file paths for scripting.

The --set flag selects which files the --detailed and --paths views operate
on:
  unknown  unrecognised dark files — the ones to investigate (default)
  dark     all dark files, including expected ones (pkg state, /dev, etc.)
  tracked  files owned by a package or SBOM
  all      every file in the image`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanFlags.detailed && scanFlags.paths {
			return fmt.Errorf("--detailed and --paths are mutually exclusive")
		}
		if !validSet(scanFlags.set) {
			return fmt.Errorf("invalid --set %q: want unknown, dark, tracked, or all", scanFlags.set)
		}

		ref, fs, err := loadFS(args, scanFlags.tar)
		if err != nil {
			return err
		}

		r, _, warnErr := analyzeImage(ref, fs)
		if warnErr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", warnErr)
		}

		// JSON always emits the structured summary, regardless of view flags.
		if scanFlags.format == "json" {
			return report.PrintJSON(os.Stdout, r)
		}

		// Plain path listing for scripting.
		if scanFlags.paths {
			sub := &report.Result{
				ImageRef:  r.ImageRef,
				Distro:    r.Distro,
				DarkFiles: selectFiles(r, fs, scanFlags.set),
			}
			if scanFlags.sizes {
				report.PrintDarkFilesDetailed(os.Stdout, sub, scanFlags.group)
			} else {
				report.PrintDarkFiles(os.Stdout, sub, scanFlags.group)
			}
			return nil
		}

		// Default text view: stats summary, optionally + per-layer breakdown.
		report.PrintStats(os.Stdout, r)

		if scanFlags.detailed {
			files := selectFiles(r, fs, scanFlags.set)
			if len(files) == 0 {
				if scanFlags.set == "unknown" {
					fmt.Println("\nNo unexpected dark files found. Use --set dark to include expected dark files.")
				} else {
					fmt.Println("\nNo files to show.")
				}
				return nil
			}
			// Tag categories whenever the selection can mix categories.
			report.PrintByLayer(os.Stdout, fs.Layers, files, scanFlags.set != "unknown")
		}
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanFlags.format, "format", "text", "Output format: text or json")
	scanCmd.Flags().BoolVarP(&scanFlags.detailed, "detailed", "d", false,
		"List dark files grouped by the layer that introduced them")
	scanCmd.Flags().BoolVar(&scanFlags.paths, "paths", false,
		"Print matching file paths only, one per line (for scripting)")
	scanCmd.Flags().StringVar(&scanFlags.set, "set", "unknown",
		"Which files the --detailed/--paths views show: unknown, dark, tracked, or all")
	scanCmd.Flags().BoolVar(&scanFlags.group, "group", false, "With --paths, group output by category")
	scanCmd.Flags().BoolVar(&scanFlags.sizes, "sizes", false, "With --paths, show file sizes")
	scanCmd.Flags().StringVar(&scanFlags.tar, "tar", "", "Load image from local OCI tar file instead of a registry")
}

func validSet(s string) bool {
	switch s {
	case "unknown", "dark", "tracked", "all":
		return true
	default:
		return false
	}
}

// selectFiles returns the files matching the named set, as CategorizedFile so
// callers can render paths, sizes, layer attribution, or categories uniformly.
func selectFiles(r *report.Result, fs *image.ImageFS, set string) []report.CategorizedFile {
	switch set {
	case "dark":
		return r.DarkFiles
	case "tracked", "all":
		dark := make(map[string]bool, len(r.DarkFiles))
		for _, f := range r.DarkFiles {
			dark[f.Path] = true
		}
		var out []report.CategorizedFile
		for _, f := range fs.Files {
			if set == "tracked" && dark[f.Path] {
				continue
			}
			out = append(out, report.CategorizedFile{File: f, Cat: report.Classify(f)})
		}
		return out
	default: // "unknown"
		return r.UnknownFiles()
	}
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
