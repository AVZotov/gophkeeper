package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/vaultsync"
)

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
			res, err := runSync(cmd, a)
			if errors.Is(err, remote.ErrUnavailable) {
				return fmt.Errorf("%w, changes are saved locally", err)
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Pushed %d, pulled %d, conflicts %d.\n", res.Pushed, res.Pulled, res.Conflicts)
			return err
		},
	}
}

// runSync syncs the local records with the server. Returns an error if there
// is no session or the sync fails.
func runSync(cmd *cobra.Command, a app) (vaultsync.Result, error) {
	ctx := cmd.Context()
	cfg, err := loadConfig()
	if err != nil {
		return vaultsync.Result{}, err
	}
	store, err := a.openStore(ctx)
	if err != nil {
		return vaultsync.Result{}, err
	}
	defer store.Close()
	st, err := loggedIn(ctx, store)
	if err != nil {
		return vaultsync.Result{}, err
	}
	_, keys, err := a.openSession(cfg)
	if err != nil {
		return vaultsync.Result{}, err
	}

	client, err := a.dialSaved(cfg, st)
	if err != nil {
		return vaultsync.Result{}, err
	}
	defer client.Close()
	client.Resume(st.Login, keys.Login, st.Token)

	res, err := vaultsync.Sync(ctx, store, client, keys.Data)
	return res, errors.Join(err, saveToken(ctx, store, client, st.Token))
}
