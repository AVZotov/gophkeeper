package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/session"
)

// newLockCmd returns the lock command. Like bw lock of Bitwarden CLI, it
// ends the session.
func newLockCmd(a app) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the vault: end the session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := lock(a); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Your vault is locked.")
			return err
		},
	}
}

// newLogoutCmd returns the logout command. It ends the session and deletes
// the local records and the state. It refuses while local changes are not
// synced, unless forced.
func newLogoutCmd(a app) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Log out: end the session and delete local data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer store.Close()

			dirty, err := store.Dirty(cmd.Context())
			if err != nil {
				return err
			}
			if len(dirty) > 0 && !force {
				return fmt.Errorf("%d local changes are not synced: run gophkeeper sync, or gophkeeper logout --force to delete them", len(dirty))
			}
			if err := lock(a); err != nil {
				return err
			}
			if err := store.Clear(cmd.Context()); err != nil {
				return fmt.Errorf("clear local database: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "You are logged out.")
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete local changes that are not synced")
	return cmd
}

// lock ends the session.
func lock(a app) error {
	path, err := a.path(sessionFile)
	if err != nil {
		return err
	}
	return session.Lock(path)
}
