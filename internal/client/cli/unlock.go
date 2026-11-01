package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

// unlockHint tells how to set the session key. The verbs are the session
// lifetime and the key, as indexed arguments.
const unlockHint = `Your vault is unlocked. The session expires in %[1]v.

Set the session key in this terminal so that commands can use it:

  bash, zsh:   export ` + sessionEnv + `="%[2]s"
  PowerShell:  $env:` + sessionEnv + `="%[2]s"
  cmd:         set "` + sessionEnv + `=%[2]s"

Or unlock and set the key at once in bash or zsh:

  export ` + sessionEnv + `=$(gophkeeper unlock --raw)
`

// newUnlockCmd returns the unlock command. Like bw unlock of Bitwarden CLI,
// it opens the envelope with the master password, starts a session and
// prints the session key.
func newUnlockCmd(a app) *cobra.Command {
	var raw bool
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault and print a session key",
		Long: "Unlock asks for the master password, unlocks the vault for " + session.TTL.String() +
			" and prints a session key. Commands take the key from " + sessionEnv +
			". A new unlock ends the previous session. If the password does not open the" +
			" local vault, unlock asks the server whether it was changed on another device.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keys, err := unlock(cmd, a)
			if err != nil {
				return err
			}
			return startSession(cmd, a, keys, raw)
		},
	}
	addRawFlag(cmd, &raw)
	return cmd
}

// addRawFlag adds the --raw flag of the commands that print a session key.
func addRawFlag(cmd *cobra.Command, raw *bool) {
	cmd.Flags().BoolVar(raw, "raw", false, "print only the session key")
}

// startSession starts a session with keys and prints its key: alone if raw
// is set, with hints how to use it otherwise.
func startSession(cmd *cobra.Command, a app, keys session.Keys, raw bool) error {
	path, err := a.path(sessionFile)
	if err != nil {
		return err
	}
	key, err := session.Unlock(path, keys, time.Now())
	if err != nil {
		return err
	}
	if raw {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), key)
	} else {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), unlockHint, session.TTL, key)
	}
	return err
}

// unlock derives the keys from the password and the saved salt and opens
// the saved envelope. If the password does not open it, the password may
// have been changed on another device: then unlock logs in with the salt
// from the server and saves the new salt and envelope. Returns an error if
// the user has not logged in or the password is wrong.
func unlock(cmd *cobra.Command, a app) (session.Keys, error) {
	ctx := cmd.Context()
	cfg, err := loadConfig()
	if err != nil {
		return session.Keys{}, err
	}
	store, err := a.openStore(ctx)
	if err != nil {
		return session.Keys{}, err
	}
	defer store.Close()
	st, err := loggedIn(ctx, store)
	if err != nil {
		return session.Keys{}, err
	}

	password, err := readPassword(cmd, passwordPrompt)
	if err != nil {
		return session.Keys{}, err
	}
	defer clear(password)
	wrapKey, loginKey, err := vaultcrypto.DeriveKeys(password, st.Salt)
	if err != nil {
		return session.Keys{}, err
	}
	dataKey, err := vaultcrypto.OpenEnvelope(wrapKey, st.Envelope)
	if errors.Is(err, vaultcrypto.ErrWrongPassword) {
		return unlockOnline(ctx, a, cfg, store, st, password)
	}
	if err != nil {
		return session.Keys{}, err
	}
	return session.Keys{Data: dataKey, Login: loginKey}, nil
}

// unlockOnline logs in with the password and the salt from the server and
// saves the new salt, envelope and token. Returns
// [vaultcrypto.ErrWrongPassword] if the server rejects the password too or
// cannot be asked.
func unlockOnline(ctx context.Context, a app, cfg config, store *storage.Store, st storage.State, password []byte) (session.Keys, error) {
	cannotAsk := func(err error) error {
		return fmt.Errorf("%w; cannot ask the server for a new password: %w", vaultcrypto.ErrWrongPassword, err)
	}
	client, err := a.dialSaved(cfg, st)
	if err != nil {
		return session.Keys{}, cannotAsk(err)
	}
	defer client.Close()

	salt, err := client.GetSalt(ctx, st.Login)
	if err != nil {
		return session.Keys{}, cannotAsk(err)
	}
	// A password change always makes a new salt.
	if bytes.Equal(salt, st.Salt) {
		return session.Keys{}, vaultcrypto.ErrWrongPassword
	}
	wrapKey, loginKey, err := vaultcrypto.DeriveKeys(password, salt)
	if err != nil {
		return session.Keys{}, err
	}
	keys, envelope, err := signIn(ctx, client, st.Login, wrapKey, loginKey)
	if errors.Is(err, remote.ErrWrongCredentials) {
		return session.Keys{}, vaultcrypto.ErrWrongPassword
	}
	if err != nil {
		return session.Keys{}, cannotAsk(err)
	}

	err = store.UpdateState(ctx, func(st *storage.State) {
		st.Salt, st.Envelope, st.Token = salt, envelope, client.Token()
	})
	if err != nil {
		return session.Keys{}, err
	}
	return keys, nil
}

// signIn logs in with the login key and opens the envelope from the server
// with the wrap key. It returns the keys for a session and the envelope.
// Returns [remote.ErrWrongCredentials] if the server rejects the login key
// and an error if the envelope does not open.
func signIn(ctx context.Context, client *remote.Client, login string, wrapKey vaultcrypto.WrapKey, loginKey vaultcrypto.LoginKey) (session.Keys, []byte, error) {
	envelope, err := client.Login(ctx, login, loginKey)
	if err != nil {
		return session.Keys{}, nil, err
	}
	dataKey, err := vaultcrypto.OpenEnvelope(wrapKey, envelope)
	if err != nil {
		return session.Keys{}, nil, fmt.Errorf("open the envelope from the server: %w", err)
	}
	return session.Keys{Data: dataKey, Login: loginKey}, envelope, nil
}
