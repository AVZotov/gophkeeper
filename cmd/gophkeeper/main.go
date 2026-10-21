package main

import (
	"os"

	"github.com/spf13/cobra"
)

// Build information, set at build time with -ldflags -X.
var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	if err := newRootCmd(version, buildDate).Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the gophkeeper command tree. The version command prints
// clientVersion and clientBuildDate.
func newRootCmd(clientVersion, clientBuildDate string) *cobra.Command {
	root := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper password manager client",
	}
	root.AddCommand(newVersionCmd(clientVersion, clientBuildDate))

	return root
}
