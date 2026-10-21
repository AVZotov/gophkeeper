package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd returns the version command, which prints the client version
// and build date.
func newVersionCmd(clientVersion, clientBuildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the client version and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "version:    %s\nbuild date: %s\n", clientVersion, clientBuildDate)
			return err
		},
	}
}
