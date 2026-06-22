# darkfiles

Find "dark" files in container images — files that exist in the image but are not
tracked by the package manager database (or, with `--sbom`, by an SBOM).

Dark files represent an unknown attack surface: they won't show up in vulnerability
scanners that rely on package databases, they can hide malware or supply-chain
tampering, and they signal image hygiene problems (leftover build artifacts, secret
files, injected binaries).

## Features

- **Auto-detects the distro** from `/etc/os-release` — no `--distro` flag needed
- **Supports Alpine, Wolfi/Chainguard, Debian/Ubuntu** package databases
- **Handles merged-usr layouts** and busybox multi-call symlinks correctly (the
  original darkfiles got negative file counts because of double-counting; this
  version deduplicates paths and resolves full symlink chains)
- **Optional SBOM mode** (`--sbom` / `--sbom-file`) — treat an SBOM as the
  authoritative source instead of the package database, to audit what the SBOM
  fails to account for. Reads in-image SPDX SBOMs (apko-generated files in
  `/var/lib/db/sbom/`) or an external SPDX JSON file
- **Reports by file count and bytes** — a 1 000-file shell script collection is
  less alarming than a single 200 MB injected binary
- **JSON output** for integration with pipelines and dashboards

## Installation

```
go install github.com/chainguard-dev/darkfiles2@latest
```

Or build from source:

```
git clone https://github.com/chainguard-dev/darkfiles2
cd darkfiles2
go build -o darkfiles .
```

## Usage

Everything is done through a single `scan` command. By default it prints a
statistics summary; flags switch on more detailed views.

### Statistics summary (default)

```
darkfiles scan alpine:latest
darkfiles scan debian:latest
darkfiles scan cgr.dev/chainguard/wolfi-base:latest
darkfiles scan --format json cgr.dev/chainguard/static:latest
```

Example output:

```
Image:          alpine:latest
Distro:         alpine
Total files:    416
Total size:     8.0 MiB
Tracked files:  411 (98.8%)
Tracked size:   8.0 MiB (100.0%)
Dark files:     5 (1.2%)
Dark size:      2.1 KiB (0.0%)
```

### Detailed view: dark files grouped by layer

`--detailed` (`-d`) appends a breakdown of dark files grouped by the layer
(Dockerfile instruction) that introduced them, with size and mode:

```
darkfiles scan -d alpine:latest
```

### Plain path list (for scripting)

`--paths` emits matching file paths, one per line:

```
darkfiles scan --paths debian:latest            # unknown files (default)
darkfiles scan --paths --sizes debian:latest    # add file sizes
darkfiles scan --paths --group debian:latest    # group by category
```

### Highlighting executable code

Among dark files, executables, libraries, and scripts are the highest-signal
subset — an unknown binary is far more concerning than a stray config file.
darkfiles identifies them by content (ELF/Mach-O/PE/shebang/ar magic bytes,
disambiguated by mode and path) and:

- adds a `Dark code:` line to the summary (`3 executables, 2 shared libraries`),
- tags each code file in the detailed/paths views (`[executable]`, `[shared library]`, `[script]`),
- highlights them in red in the `--detailed` view when writing to a terminal.

Use `--code` to show only code files (composes with `--set`):

```
darkfiles scan -d --code img            # dark binaries/libs/scripts, by layer
darkfiles scan --paths --code img       # just their paths, for scripting
```

The JSON output includes a `dark_code` object with per-kind counts.

### Selecting which files to show

The `--set` flag controls which files the `--detailed` and `--paths` views
operate on (the summary always reports on everything):

```
darkfiles scan -d --set unknown img    # unrecognised dark files only (default)
darkfiles scan -d --set dark    img    # all dark files, incl. expected ones
darkfiles scan --paths --set tracked img
darkfiles scan --paths --set all img
```

| `--set`   | meaning                                                  |
|-----------|----------------------------------------------------------|
| `unknown` | unrecognised dark files (default)                        |
| `dark`    | all dark files, including expected (pkg state, `/dev`, …) |
| `tracked` | files owned by a package or SBOM                         |
| `all`     | every file in the image                                  |

### Load from a local tar

```
docker save myimage:latest | darkfiles scan --tar /dev/stdin
darkfiles scan --tar ./myimage.tar -d --set dark
```

## What counts as "dark"?

A file is dark if:

1. It is **not listed** in the tracked-file source. By default that's the
   installed-package manifest (`/lib/apk/db/installed`, `/usr/lib/apk/db/installed`,
   `/var/lib/dpkg/info/*.list`). In `--sbom` mode it's instead the SPDX SBOM — an
   external file (`--sbom-file`) or apko's per-package SBOMs in `/var/lib/db/sbom/`.
   The package database and the SBOM are mutually exclusive sources, not merged.
2. It is **not a symlink** whose fully-resolved target is a tracked file — this
   correctly handles multi-call busybox, merged-usr hierarchies, etc.

The percentage shown is `dark_files / total_files` and `dark_bytes / total_bytes`
independently, because a single large binary is more concerning than many tiny
config files.

## Why not the original darkfiles?

The original [chainguard-dev/darkfiles](https://github.com/chainguard-dev/darkfiles)
was archived after several correctness issues:

- **Negative file counts** ([#3](https://github.com/chainguard-dev/darkfiles/issues/3))
  — caused by not deduplicating the tracked-file set; a file owned by multiple
  packages was subtracted multiple times
- **No OS auto-detection** ([#7](https://github.com/chainguard-dev/darkfiles/issues/7))
  — required manual `--distro` flag
- **No SBOM support** — couldn't use in-image SBOMs to classify files
- **Symlink handling** — busybox multi-call symlinks and merged-usr layouts were
  not resolved, causing nearly all of Alpine's `bin/` to appear dark

This rewrite addresses all of the above.

## Limitations

- **RPM-based images** (RHEL, Fedora, Rocky): the RPM database is a BDB/SQLite
  file that requires CGO or native tooling to read. A pure-Go implementation is
  on the roadmap; for now RPM images will report all files as dark.
- **Multi-platform images**: the tool pulls the platform that matches the host
  by default (via `crane`'s default keychain).
- **Opaque layers**: `.wh.` whiteout entries are correctly handled by
  `crane.Export`'s flattening logic.
