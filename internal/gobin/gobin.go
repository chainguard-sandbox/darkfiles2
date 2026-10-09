// Package gobin recognises Go binaries by their embedded build information.
//
// The Go toolchain records the main module, its dependencies (with versions and
// checksums), and the Go version in every binary it builds. Vulnerability
// scanners such as Grype, Trivy, and Syft read this metadata directly, so a Go
// binary is not invisible to them even when no package manager tracks it.
package gobin

import (
	"bytes"
	"debug/buildinfo"
)

// IsGoBinary reports whether data is an executable (ELF, Mach-O, PE, ...) with
// readable Go build information. Stripped-down or garbled binaries whose build
// info cannot be parsed are not recognised.
func IsGoBinary(data []byte) bool {
	_, err := buildinfo.Read(bytes.NewReader(data))
	return err == nil
}
