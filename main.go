package main

import (
	"github.com/chainguard-sandbox/darkfiles2/cmd"
)

// Populated at build time by GoReleaser via -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
