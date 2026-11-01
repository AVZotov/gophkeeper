package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

// newChangePasswordCmd returns the change-password command.
func newChangePasswordCmd(a app) *cobra.Command {
	return &cobra.Command{
		Use:   "change-password",
		Short: "Change the master password",
		Long: "Change-password asks for the current and the new master password and changes it" +
			" on the server. Records are not encrypted anew. The session goes on with the same key;" +
			" other devices have to unlock with the new password.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := changePassword(cmd, a); err != nil {
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "Your master password is changed.")
			return err
		},
	}
}

// changePassword seals the data key of the session with a key from the new
// password and replaces the salt, the login key and the envelope on the
// server, in the state and in the session, then logs in with the new login
// key. Returns an error if there is no session, the current password is
// wrong or the server rejects the change.
func changePassword(cmd *cobra.Command, a app) error {
	ctx := cmd.Context()
	v, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer v.Close()
	st, keys := v.state, v.keys

	// An unlocked terminal is not enough to change the password.
	current, err := readPassword(cmd, currentPasswordPrompt)
	if err != nil {
		return err
	}
	defer clear(current)
	wrapKey, oldLoginKey, err := vaultcrypto.DeriveKeys(current, st.Salt)
	if err != nil {
		return err
	}
	if _, err := vaultcrypto.OpenEnvelope(wrapKey, st.Envelope); err != nil {
		return err
	}

	password, err := readNewPassword(cmd, newPasswordPrompt, repeatNewPasswordPrompt)
	if err != nil {
		return err
	}
	defer clear(password)
	salt := vaultcrypto.NewSalt()
	wrapKey, loginKey, err := vaultcrypto.DeriveKeys(password, salt)
	if err != nil {
		return err
	}
	envelope := vaultcrypto.SealEnvelope(wrapKey, keys.Data)

	client, err := a.dialSaved(v.cfg, st)
	if err != nil {
		return err
	}
	defer client.Close()
	client.Resume(st.Login, keys.Login, st.Token)
	if err := client.ChangePassword(ctx, oldLoginKey, salt, loginKey, envelope); err != nil {
		return err
	}

	// The server has the new password now. The state goes first: unlock needs
	// it, and the session and the token can be got again with the password.
	err = v.store.UpdateState(ctx, func(st *storage.State) { st.Salt, st.Envelope = salt, envelope })
	if err != nil {
		return err
	}
	keys.Login = loginKey
	if err := session.Update(v.sessionPath, v.cfg.Session, keys, time.Now()); err != nil {
		return err
	}
	// The change revoked the token.
	if _, err := client.Login(ctx, st.Login, loginKey); err != nil {
		return fmt.Errorf("log in with the new password: %w", err)
	}
	return saveToken(ctx, v.store, client, st.Token)
}
