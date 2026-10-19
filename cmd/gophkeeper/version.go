package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd returns the version subcommand, which prints the client
// version and build date.
func newVersionCmd(version, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client version and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "version:    %s\nbuild date: %s\n", version, buildDate)
			return err
		},
	}
}
