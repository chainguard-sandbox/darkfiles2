# darkfiles

Find "dark" files in container images — files that exist in the image but are not
tracked by the package manager database.

Dark files represent an unknown attack surface: they won't show up in vulnerability
scanners that rely on package databases, they can hide malware or supply-chain
tampering, and they signal image hygiene problems (leftover build artifacts, secret
files, injected binaries).

## Features

- **Auto-detects the distro** from `/etc/os-release` — no `--distro` flag needed
- **Supports Alpine, Wolfi/Chainguard, Debian/Ubuntu** package databases
- **Reports by file count and bytes** — a 1,000-file shell script collection is
  less alarming than a single 200 MB injected binary
- **Cross-references an SBOM** (`--sbom`) — fetches the image's SPDX SBOM
  attestation and excludes the files it documents from the dark set, reporting
  them separately
- **Accounts for Go binaries** (`--detect-go`) — Go executables embed build
  info (module, dependencies, versions) that scanners read directly, so they
  can be reported separately rather than as dark
- **Detects vendored libraries** (`--detect-libs`) — scans binaries for
  statically-linked libraries using string-signature heuristics ported from 
  cve-bin-tool
- **JSON output** for integration with pipelines and dashboards

## Installation

```
go install github.com/chainguard-sandbox/darkfiles2@latest
```

Or build from source:

```
git clone https://github.com/chainguard-sandbox/darkfiles2
cd darkfiles2
go build -o darkfiles .
```

## Usage

Run `darkfiles <image>` to scan an image. By default it prints a statistics
summary; flags switch on more detailed views.

### Statistics summary (default)

```
darkfiles alpine:latest
darkfiles debian:latest
darkfiles cgr.dev/chainguard/wolfi-base:latest
darkfiles --format json cgr.dev/chainguard/static:latest
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
darkfiles -d alpine:latest
```

### Plain path list (for scripting)

`--paths` emits matching file paths, one per line:

```
darkfiles --paths debian:latest            # unknown files (default)
darkfiles --paths --sizes debian:latest    # add file sizes
darkfiles --paths --group debian:latest    # group by category
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
darkfiles -d --code img            # dark binaries/libs/scripts, by layer
darkfiles --paths --code img       # just their paths, for scripting
```

The JSON output includes a `dark_code` object with per-kind counts.

### Cross-referencing against an SBOM

`--sbom` fetches the image's SPDX SBOM — published by DHI (Docker Hardened
Images) and similar builders as an in-toto attestation attached via the OCI
referrers API — and extracts every file path it records. Dark files that the
SBOM documents are **not** treated as dark: they are accounted for by the SBOM,
so they move into their own `In SBOM` bucket between tracked and dark:

```
darkfiles --sbom dhi.io/vault:2
```

```
Image:          dhi.io/vault:2
Distro:         debian
Total files:    1050
Total size:     432.4 MiB
Tracked files:  287 (27.3%)
Tracked size:   13.2 MiB (3.1%)
In SBOM:        644 (61.3%)
In SBOM size:   418.7 MiB (96.8%)
Dark files:     119 (11.3%)
Dark size:      536.8 KiB (0.1%)
```

The `Dark file breakdown` and `Dark code` lines then describe only the files
that remain unaccounted for — neither tracked by a package nor documented by the
SBOM (nor, with `--detect-go`, identified as a Go binary; see below).
`Tracked`, `In SBOM`, `Go binaries` (with `--detect-go`), and `Dark` partition
every file in the image.

A registry-fetched SBOM is only trusted once its cosign signature is verified.
darkfiles verifies the SPDX attestation against Docker's published DHI signing
key. If verification fails — a non-DHI image, a missing
signature, or a bad one — the SBOM is **not** applied and the files stay dark,
with a warning. Override the key with `--sbom-key <pem>`, or skip verification
entirely with `--insecure-sbom`. A local `--sbom-file` is trusted as supplied and
is not verified.

Use `--sbom-file <path>` to cross-reference against a local SPDX file (an
in-toto statement or a bare SPDX document) instead of fetching from the
registry; this is required when scanning a `--tar` image. List the
SBOM-accounted paths with `--set in-sbom`:

```
darkfiles --sbom --paths --set in-sbom dhi.io/vault:2
darkfiles --sbom-file ./vault.spdx.json --tar ./vault.tar
```

The JSON output gains an `in_sbom` object (`{count, bytes}`) whenever an SBOM
was applied, and `dark_files`/`dark_bytes` exclude the SBOM-accounted files.

### Go binaries

The Go toolchain embeds build information in every binary it produces: the main
module, each dependency with its version and checksum, and the Go version.
Vulnerability scanners such as Grype, Trivy, and Syft read this metadata
directly, so an untracked Go binary is not invisible to them in the way an
arbitrary unknown binary is.

By default darkfiles counts Go binaries like any other untracked file: as dark.
`--detect-go` inspects each dark executable and shared library for Go build info
(using `debug/buildinfo`), and moves those that carry it — along with any dark
symlinks or hard links to them — into their own `Go binaries` bucket rather than
counting them as dark:

```
darkfiles --detect-go registry:2
```

```
Image:           registry:2
Distro:          alpine
Total files:     879
Total size:      24.0 MiB
Tracked files:   866 (98.5%)
Tracked size:    7.2 MiB (30.2%)
Go binaries:     1 (0.1%)
Go binary size:  16.7 MiB (69.8%)
Dark files:      12 (1.4%)
Dark size:       14.0 KiB (0.1%)
```

Without `--detect-go`, `/bin/registry` would be among the dark files (16.7 MiB
dark). Use it when your scanner reads Go build info; leave it off to treat every
binary outside the package manager as unaccounted for.

The `Dark file breakdown` and `Dark code` lines then exclude the Go binaries.
Binaries whose build info cannot be read (e.g. deliberately stripped of it) stay
dark. When `--sbom` is also given, the SBOM takes precedence: a Go binary the
SBOM documents is counted under `In SBOM`, not `Go binaries`. A dark symlink or
hard link to such a binary (or to a package-owned Go binary) is still counted
under `Go binaries`.

List the Go binaries with `--set go`, or scan them for vendored libraries with
`--detect-libs` (`--set go` requires `--detect-go`):

```
darkfiles --detect-go --paths --set go registry:2
darkfiles --detect-go --detect-libs --set go registry:2
```

The JSON output gains a `go_binaries` object (`{count, bytes}`) whenever
`--detect-go` is given — including `{"count": 0, ...}` when none were found — and
`dark_files`/`dark_bytes` exclude them.

Detection reads file content, so it costs a second pass over the image layers
when the image has dark executables or shared libraries (and nothing otherwise).
Files are inspected one at a time rather than held in memory together.

### Detecting vendored libraries

Statically linked libraries are often missed from SBOMs, resulting in another
kind of "dark matter". `--detect-libs` extracts printable strings from each
selected file and matches them against a database of ~450 per-library
signatures (ported from [cve-bin-tool](https://github.com/intel/cve-bin-tool)) to
recover which libraries — and, where possible, which versions — are baked in:

```
darkfiles --detect-libs --code img            # scan dark code files
darkfiles --detect-libs --code --set all img  # scan every code file
darkfiles --detect-libs --format json img     # machine-readable results
```

It operates on the same selection as the other views (`--set` and `--code`), so
`--detect-libs --code` targets dark executables and libraries — usually what you
want. With `--detect-go`, Go binaries leave the dark set (see
[Go binaries](#go-binaries)) and so are not included; add `--set go` to scan
them. It is **not limited to dark files**: because it honours `--set`, you can
detect vendored libraries in package-owned binaries too:

```
darkfiles --detect-libs --code --set tracked img  # only package-owned code
darkfiles --detect-libs --code --set all img      # every binary, dark or not
```

Each detected library is listed under its file as `library  version(s)  vendor(s)`.
Example:

```
/usr/bin/busybox
  busybox  1.38.0  busybox

/usr/lib/libcrypto.so.3
  openssl  3.6.4   openssl

Scanned 29 file(s); 27 with detected libraries.
```

This is signature-based detection, not a bill of materials: false positives
(e.g. a compiler build-id string reported as `gcc`) and false negatives are
inherent to the heuristic. Detection is based purely on the file's contents;
presence with no parseable version is reported as `UNKNOWN`. Tune string
extraction with `--detect-libs-min-length`.

The feature is off by default and reads full file content (a second pass over
the image layers), unlike the metadata-only default scan.

### Selecting which files to show

The `--set` flag controls which files the `--detailed`, `--paths`, and
`--detect-libs` views operate on (the summary always reports on everything):

```
darkfiles -d --set unknown img    # unrecognised dark files only (default)
darkfiles -d --set dark    img    # all dark files, incl. expected ones
darkfiles --paths --set tracked img
darkfiles --paths --set all img
darkfiles --detect-go --paths --set go img  # Go binaries (see above)
```

| `--set`   | meaning                                                  |
|-----------|----------------------------------------------------------|
| `unknown` | unrecognised dark files (default)                        |
| `dark`    | all dark files, including expected (pkg state, `/dev`, …) |
| `tracked` | files owned by a package                                 |
| `all`     | every file in the image                                  |
| `in-sbom` | files accounted for by the SBOM (requires `--sbom`)      |
| `go`      | Go binaries accounted for by their build info (requires `--detect-go`) |

### Load from a local tar

```
docker save myimage:latest | darkfiles --tar /dev/stdin
darkfiles --tar ./myimage.tar -d --set dark
```

## What counts as "dark"?

A file is dark if:

1. It is **not listed** in any installed-package manifest (`/lib/apk/db/installed`,
   `/usr/lib/apk/db/installed`, `/var/lib/dpkg/info/*.list`)
2. It is **not a symlink** whose fully-resolved target is a tracked file — this
   correctly handles multi-call busybox, merged-usr hierarchies, etc.
3. It is **not documented by the image's SBOM**, when `--sbom` is given
4. With `--detect-go`, it is **not a Go binary** with readable embedded build
   info (or a symlink or hard link to one) — scanners read that build info directly, so such
   binaries are visible to them

Each untracked file is accounted for by the first rule that matches, so a Go
binary that the SBOM documents is counted as `In SBOM`.

The percentage shown is `dark_files / total_files` and `dark_bytes / total_bytes`
independently, because a single large binary is more concerning than many tiny
config files.

## Why the 2 in Darkfiles2?

There was an original [chainguard-dev/darkfiles](https://github.com/chainguard-dev/darkfiles) project that was archived. This is a rewrite that fixes several shortcomings and improves reporting.


## Limitations

- **RPM-based images** (RHEL, Fedora, Rocky): there is currently no support for RPM based distros.
- **Multi-platform images**: the tool pulls the platform that matches the host.
