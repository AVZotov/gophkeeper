package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/session"
)

// newLockCmd returns the lock command. Like bw lock of Bitwarden CLI, it
// ends the session.
func newLockCmd(f files) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Lock the vault: end the session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := lock(f); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Your vault is locked.")
			return err
		},
	}
}

// newLogoutCmd returns the logout command. It ends the session and deletes
// the local records and the state.
func newLogoutCmd(f files) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out: end the session and delete local data",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := lock(f); err != nil {
				return err
			}
			store, err := f.openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.Clear(cmd.Context()); err != nil {
				return fmt.Errorf("clear local database: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "You are logged out.")
			return err
		},
	}
}

// lock ends the session.
func lock(f files) error {
	path, err := f.path(sessionFile)
	if err != nil {
		return err
	}
	return session.Lock(path)
}
