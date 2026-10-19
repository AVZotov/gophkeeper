package main

import (
	"os"

	"github.com/spf13/cobra"
)

// Build information, replaced at build time via -ldflags -X.
var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	if err := newRootCmd(version, buildDate).Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the gophkeeper command tree. version and buildDate are
// printed by the version subcommand.
func newRootCmd(version, buildDate string) *cobra.Command {
	root := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper password manager client",
	}
	root.AddCommand(newVersionCmd(version, buildDate))

	return root
}
