# darkfiles

Find "dark" files in container images — files that exist in the image but are not
tracked by any package manager or embedded SBOM.

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
- **Reads in-image SBOMs** (apko-generated SPDX files in `/var/lib/db/sbom/`)
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

### Scan an image and print statistics

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

### List dark files

```
# List dark (untracked) files — default
darkfiles list debian:latest

# Include file sizes
darkfiles list --detailed debian:latest

# Show all files, or only tracked files
darkfiles list --set all debian:latest
darkfiles list --set tracked debian:latest
```

### Load from a local tar

```
docker save myimage:latest | darkfiles scan --tar /dev/stdin
darkfiles list --tar ./myimage.tar --detailed
```

## What counts as "dark"?

A file is dark if:

1. It is **not listed** in any installed-package manifest (`/lib/apk/db/installed`,
   `/usr/lib/apk/db/installed`, `/var/lib/dpkg/info/*.list`)
2. It is **not a symlink** whose fully-resolved target is a tracked file — this
   correctly handles multi-call busybox, merged-usr hierarchies, etc.
3. It is **not referenced** by an embedded SPDX SBOM (e.g. apko's per-package
   SBOM files in `/var/lib/db/sbom/`)

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
