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
- **Handles merged-usr layouts** and busybox multi-call symlinks correctly (the
  original darkfiles got negative file counts because of double-counting; this
  version deduplicates paths and resolves full symlink chains)
- **Reports by file count and bytes** — a 1 000-file shell script collection is
  less alarming than a single 200 MB injected binary
- **Cross-references an SBOM** (`--sbom`) — fetches the image's SPDX SBOM
  attestation and excludes the files it documents from the dark set, reporting
  them separately (primarily for DHI images)
- **Fingerprints vendored libraries** (`--fingerprint`) — scans binaries for
  statically-linked libraries and versions no package manager tracks, using
  string-fingerprint heuristics ported from cve-bin-tool
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
SBOM. `Tracked`, `In SBOM`, and `Dark` partition every file in the image.

Because the SBOM determines which files are excluded from the dark set, a
registry-fetched SBOM is only trusted once its cosign signature is verified.
darkfiles verifies the SPDX attestation against Docker's published DHI signing
key (embedded in the binary; Rekor is ignored, as DHI does not always publish to
the transparency log). If verification fails — a non-DHI image, a missing
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

### Fingerprinting vendored libraries

A dark binary is often dark because it statically links libraries the package
manager never recorded. `--fingerprint` extracts printable strings from each
selected file and matches them against a database of ~450 per-library
signatures (ported from [cve-bin-tool](https://github.com/intel/cve-bin-tool)
via [darkrustmaster](https://github.com/chainguard-sandbox/darkrustmaster)) to
recover which libraries — and, where possible, which versions — are baked in:

```
darkfiles --fingerprint --code img          # fingerprint dark code files
darkfiles --fingerprint --code --set all img # fingerprint every code file
darkfiles --fingerprint --format json img   # machine-readable results
```

It operates on the same selection as the other views (`--set` and `--code`), so
`--fingerprint --code` targets dark executables and libraries — usually what you
want. Example:

```
/usr/bin/busybox
  busybox  1.38.0  busybox  contents

/usr/lib/libcrypto.so.3
  openssl  3.6.4   openssl  contents

Fingerprinted 29 file(s); 27 with detected libraries.
```

This is fingerprinting, not a bill of materials: false positives (e.g. a
compiler build-id string reported as `gcc`) and false negatives are inherent to
the heuristic. Presence with no parseable version is reported as `UNKNOWN`. Tune
string extraction with `--fingerprint-min-length`, and add
`--fingerprint-use-filename` to also treat a matching file name as evidence.

The feature is off by default and reads full file content (a second pass over
the image layers), unlike the metadata-only default scan.

### Selecting which files to show

The `--set` flag controls which files the `--detailed` and `--paths` views
operate on (the summary always reports on everything):

```
darkfiles -d --set unknown img    # unrecognised dark files only (default)
darkfiles -d --set dark    img    # all dark files, incl. expected ones
darkfiles --paths --set tracked img
darkfiles --paths --set all img
```

| `--set`   | meaning                                                  |
|-----------|----------------------------------------------------------|
| `unknown` | unrecognised dark files (default)                        |
| `dark`    | all dark files, including expected (pkg state, `/dev`, …) |
| `tracked` | files owned by a package                                 |
| `all`     | every file in the image                                  |
| `in-sbom` | files accounted for by the SBOM (requires `--sbom`)      |

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

The percentage shown is `dark_files / total_files` and `dark_bytes / total_bytes`
independently, because a single large binary is more concerning than many tiny
config files.

## Why the 2 in Darkfiles2?

There was an original [chainguard-dev/darkfiles](https://github.com/chainguard-dev/darkfiles) project that was archived. This is a rewrite that fixes several shortcomings and improves reporting.


## Limitations

- **RPM-based images** (RHEL, Fedora, Rocky): there is currently no support for RPM based distros.
- **Multi-platform images**: the tool pulls the platform that matches the host.
