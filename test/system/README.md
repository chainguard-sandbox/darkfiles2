# System snapshot tests

High-level regression tests that run the built `darkfiles` binary against real,
digest-pinned images and compare the JSON output to recorded baselines in
`testdata/`. If a code change alters the analysis for a known image, these tests
fail — a signal that something (intended or not) changed.

They pull full images from public registries (`cgr.dev`, `dhi.io`), so they are
**opt-in** and skipped by default (and under `-short`).

## Run

```sh
RUN_SYSTEM_TESTS=1 go test ./test/system/...
```

## Update baselines after an intentional change

```sh
go test ./test/system/... -update
```

Review the resulting `testdata/*.json` diff before committing — it should reflect
only the change you made.

## Pinned images

Each image is pinned to its **linux/amd64 manifest digest** (not the multi-arch
index) so the pulled bytes, and therefore the output, are identical regardless of
host architecture:

- `cgr.dev/chainguard/static` — Wolfi/apk, minimal
- `cgr.dev/chainguard/wolfi-base` — Wolfi/apk, more packages
- `dhi.io/redis` — Debian/dpkg; also exercises signed SPDX SBOM verification
  (`--sbom`) and reclassification

To bump an image, update the digest const in `system_test.go`, run with
`-update`, and commit the new baseline.
