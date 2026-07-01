// Package system holds high-level snapshot ("golden") tests that run the built
// darkfiles binary against real, digest-pinned images and compare the JSON
// output to a recorded baseline. Their purpose is regression detection: if a
// change alters the analysis output for a known image, these tests fail.
//
// They pull full images from public registries, so they are opt-in:
//
//	RUN_SYSTEM_TESTS=1 go test ./test/system/...
//
// Regenerate the baselines after an intentional output change:
//
//	go test ./test/system/... -update
//
// Images are pinned to their linux/amd64 manifest digest (not the multi-arch
// index) so the pulled bytes — and therefore the output — are identical
// regardless of the host architecture.
package system

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "regenerate golden files")

var binPath string

// enabled reports whether the system tests should actually run (vs. self-skip).
func enabled() bool { return os.Getenv("RUN_SYSTEM_TESTS") != "" || *update }

func TestMain(m *testing.M) {
	flag.Parse()
	if !enabled() {
		os.Exit(m.Run()) // individual tests self-skip
	}
	dir, err := os.MkdirTemp("", "darkfiles-sys")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "darkfiles")
	build := exec.Command("go", "build", "-o", binPath, "../..")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building darkfiles: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// Images pinned to their linux/amd64 manifest digest for reproducibility.
const (
	// Chainguard, Wolfi/apk — minimal.
	staticImg = "cgr.dev/chainguard/static@sha256:1fe35025bd06652914560fd01af12a705c645c5566a8d40766b2a4769f33a824"
	// Chainguard, Wolfi/apk — more packages.
	wolfiBaseImg = "cgr.dev/chainguard/wolfi-base@sha256:eba430503496d7a3b3bbf96cb0656e1daa37b6044c61c362778b7e17d371db3a"
	// DHI, Debian/dpkg — also carries a signed SPDX SBOM attestation.
	redisImg = "dhi.io/redis@sha256:66bdfc025c61d246509621e078846ab4c9a33c7125fe55450d55e7c8a853c4f9"
)

func TestSnapshots(t *testing.T) {
	if testing.Short() || !enabled() {
		t.Skip("system test: set RUN_SYSTEM_TESTS=1 (or pass -update) to run")
	}

	cases := []struct {
		name   string
		golden string
		args   []string
	}{
		{"static", "static.json", []string{"--format", "json", staticImg}},
		{"wolfi-base", "wolfi-base.json", []string{"--format", "json", wolfiBaseImg}},
		{"redis", "redis.json", []string{"--format", "json", redisImg}},
		// Exercises the SBOM signature-verification + reclassification path.
		{"redis-sbom", "redis-sbom.json", []string{"--sbom", "--format", "json", redisImg}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runDarkfiles(t, tc.args...)
			goldenPath := filepath.Join("testdata", tc.golden)

			if *update {
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("writing golden: %v", err)
				}
				t.Logf("updated %s", goldenPath)
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("reading golden (run with -update to create): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output for %s changed.\n--- want ---\n%s\n--- got ---\n%s",
					tc.name, want, got)
			}
		})
	}
}

// runDarkfiles runs the built binary and returns stdout, failing on nonzero exit
// (stderr, e.g. an unverified-SBOM warning, is surfaced via the test log).
func runDarkfiles(t *testing.T, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("darkfiles %v failed: %v\nstderr:\n%s", args, err, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Logf("stderr:\n%s", stderr.String())
	}
	return stdout.Bytes()
}
