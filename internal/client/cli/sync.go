package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/vaultsync"
)

// syncReport prints the [vaultsync.Result] of a sync.
const syncReport = "Pushed %d, pulled %d, conflicts %d.\n"

// newSyncCmd returns the sync command.
func newSyncCmd(a app) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Push local changes to the server and pull changes from it",
		Long: "Sync pushes local changes first, then pulls the changes made on other devices." +
			" If a record was changed both here and on another device, the other change is kept" +
			" and the local one is saved as a copy with \"" + vaultsync.ConflictSuffix + "\" in its name.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := a.openVault(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			res, err := v.sync(cmd.Context())
			if errors.Is(err, remote.ErrUnavailable) {
				return errSavedLocally
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), syncReport, res.Pushed, res.Pulled, res.Conflicts)
			return err
		},
	}
}
