package cmd

import (
	"fmt"
	"os"

	"github.com/chainguard-sandbox/darkfiles2/internal/image"
	"github.com/chainguard-sandbox/darkfiles2/internal/pkgdb"
	"github.com/chainguard-sandbox/darkfiles2/internal/report"
	"github.com/chainguard-sandbox/darkfiles2/internal/sbom"
	"github.com/spf13/cobra"
)

var scanFlags struct {
	format   string
	detailed bool
	paths    bool
	set      string
	group    bool
	sizes    bool
	code     bool
	tar      string
	sbom     bool
	sbomFile string
}

func runScan(cmd *cobra.Command, args []string) error {
	if scanFlags.detailed && scanFlags.paths {
		return fmt.Errorf("--detailed and --paths are mutually exclusive")
	}
	if !validSet(scanFlags.set) {
		return fmt.Errorf("invalid --set %q: want unknown, dark, tracked, all, or in-sbom", scanFlags.set)
	}
	sbomEnabled := scanFlags.sbom || scanFlags.sbomFile != ""
	if scanFlags.set == "in-sbom" && !sbomEnabled {
		return fmt.Errorf("--set in-sbom requires --sbom or --sbom-file")
	}

	ref, fs, err := loadFS(args, scanFlags.tar)
	if err != nil {
		return err
	}

	r, _, warnErr := analyzeImage(ref, fs)
	if warnErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", warnErr)
	}

	if sbomEnabled {
		paths, err := loadSBOM(args, scanFlags.tar, scanFlags.sbomFile)
		if err != nil {
			return fmt.Errorf("cross-referencing SBOM: %w", err)
		}
		r.ApplySBOM(paths)
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
			DarkFiles: selectFiles(r, fs, scanFlags.set, scanFlags.code),
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

	if !scanFlags.detailed {
		if r.DarkCount() > 0 {
			fmt.Println("\nUse -d to see further detail on dark file findings.")
		}
		return nil
	}

	files := selectFiles(r, fs, scanFlags.set, scanFlags.code)
	if len(files) == 0 {
		switch {
		case scanFlags.code:
			fmt.Println("\nNo dark code files found.")
		case scanFlags.set == "unknown":
			fmt.Println("\nNo unexpected dark files found. Use --set dark to include expected dark files.")
		default:
			fmt.Println("\nNo files to show.")
		}
		return nil
	}
	// Tag categories whenever the selection can mix categories.
	report.PrintByLayer(os.Stdout, fs.Layers, files, scanFlags.set != "unknown", isTerminal(os.Stdout))
	return nil
}

func init() {
	rootCmd.Flags().StringVar(&scanFlags.format, "format", "text", "Output format: text or json")
	rootCmd.Flags().BoolVarP(&scanFlags.detailed, "detailed", "d", false,
		"List dark files grouped by the layer that introduced them")
	rootCmd.Flags().BoolVar(&scanFlags.paths, "paths", false,
		"Print matching file paths only, one per line (for scripting)")
	rootCmd.Flags().StringVar(&scanFlags.set, "set", "unknown",
		"Which files the --detailed/--paths views show: unknown, dark, tracked, all, or in-sbom")
	rootCmd.Flags().BoolVar(&scanFlags.group, "group", false, "With --paths, group output by category")
	rootCmd.Flags().BoolVar(&scanFlags.sizes, "sizes", false, "With --paths, show file sizes")
	rootCmd.Flags().BoolVar(&scanFlags.code, "code", false,
		"Show only code files: executables, shared/static libraries, and scripts")
	rootCmd.Flags().StringVar(&scanFlags.tar, "tar", "", "Load image from local OCI tar file instead of a registry")
	rootCmd.Flags().BoolVar(&scanFlags.sbom, "sbom", false,
		"Cross-reference dark files against the image's SPDX SBOM attestation and report which are listed in it")
	rootCmd.Flags().StringVar(&scanFlags.sbomFile, "sbom-file", "",
		"Cross-reference against a local SPDX SBOM file instead of fetching from the registry (implies --sbom)")
}

func validSet(s string) bool {
	switch s {
	case "unknown", "dark", "tracked", "all", "in-sbom":
		return true
	default:
		return false
	}
}

// selectFiles returns the files matching the named set, as CategorizedFile so
// callers can render paths, sizes, layer attribution, or categories uniformly.
// When codeOnly is set, the result is filtered to executable code.
func selectFiles(r *report.Result, fs *image.ImageFS, set string, codeOnly bool) []report.CategorizedFile {
	var files []report.CategorizedFile
	switch set {
	case "in-sbom":
		files = r.SBOMFiles
	case "dark":
		files = r.DarkFiles
	case "tracked", "all":
		dark := make(map[string]bool, len(r.DarkFiles))
		for _, f := range r.DarkFiles {
			dark[f.Path] = true
		}
		for _, f := range fs.Files {
			if set == "tracked" && dark[f.Path] {
				continue
			}
			files = append(files, report.CategorizedFile{File: f, Cat: report.Classify(f)})
		}
	default: // "unknown"
		files = r.UnknownFiles()
	}

	if !codeOnly {
		return files
	}
	var code []report.CategorizedFile
	for _, f := range files {
		if f.Kind.IsCode() {
			code = append(code, f)
		}
	}
	return code
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

// loadSBOM returns the set of file paths recorded in the image's SBOM, either
// fetched from the registry (by image reference) or read from a local file.
// Fetching from the registry needs a real image reference, so it is incompatible
// with --tar unless --sbom-file is also supplied.
func loadSBOM(args []string, tarPath, sbomFile string) (map[string]struct{}, error) {
	ref := ""
	if len(args) > 0 {
		ref = args[0]
	}
	if sbomFile == "" {
		if tarPath != "" {
			return nil, fmt.Errorf("--sbom fetches the SBOM attestation from the registry and cannot be used with --tar; supply the SBOM with --sbom-file instead")
		}
		if ref == "" {
			return nil, fmt.Errorf("--sbom requires an image reference")
		}
	}

	var paths map[string]struct{}
	err := withSpinner("Fetching and cross-referencing SBOM", func() error {
		var e error
		paths, e = sbom.FilePaths(ref, sbomFile)
		return e
	})
	return paths, err
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
