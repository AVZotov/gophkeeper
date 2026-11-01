package main

import (
	"os"

	"github.com/AVZotov/gophkeeper/internal/client/cli"
)

// Build information, set at build time with -ldflags -X.
var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	if err := cli.NewRootCmd(version, buildDate).Execute(); err != nil {
		os.Exit(1)
	}
}
