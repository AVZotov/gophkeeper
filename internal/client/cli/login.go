package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
	"github.com/AVZotov/gophkeeper/internal/client/vaultsync"
)

// newRegisterCmd returns the register command. It creates a user on the
// server and logs in as the login command does.
func newRegisterCmd(a app) *cobra.Command {
	var (
		flags serverFlags
		raw   bool
	)
	cmd := &cobra.Command{
		Use:   "register LOGIN",
		Short: "Create a user on the server, log in and unlock the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys, err := enter(cmd, a, flags, args[0], true)
			if err != nil {
				return err
			}
			return startSession(cmd, a, keys, raw)
		},
	}
	flags.add(cmd)
	addRawFlag(cmd, &raw)
	return cmd
}

// newLoginCmd returns the login command. Like bw login of Bitwarden CLI, it
// logs in to the server, saves what the client needs to work offline and
// starts a session, printing its key as unlock does.
func newLoginCmd(a app) *cobra.Command {
	var (
		flags serverFlags
		raw   bool
	)
	cmd := &cobra.Command{
		Use:   "login LOGIN",
		Short: "Log in to the server and unlock the vault",
		Long: "Login asks for the master password, logs in to the server, starts a session" +
			" as unlock does and syncs the records. The server address and the CA certificate" +
			" are saved for the next commands. The local vault belongs to one user: to log in" +
			" as another one, run gophkeeper logout first.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys, err := enter(cmd, a, flags, args[0], false)
			if err != nil {
				return err
			}
			if err := startSession(cmd, a, keys, raw); err != nil {
				return err
			}
			syncAfterLogin(cmd, a, keys)
			return nil
		},
	}
	flags.add(cmd)
	addRawFlag(cmd, &raw)
	return cmd
}

// enter logs in as login, registering the user first if register is set,
// and saves the state. It returns the keys for a session. Returns an error
// if another user or another server is logged in to, the CA is not given or
// the server rejects the login.
func enter(cmd *cobra.Command, a app, flags serverFlags, login string, register bool) (session.Keys, error) {
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

	saved, err := store.State(ctx)
	switch {
	case errors.Is(err, storage.ErrNoState):
	case err != nil:
		return session.Keys{}, err
	case register || saved.Login != login:
		return session.Keys{}, fmt.Errorf("logged in as %s, run gophkeeper logout first", saved.Login)
	}
	server := cmp.Or(cfg.Server, flags.server, saved.ServerAddress, defaultServer)
	// The local records and the last revision belong to the saved server.
	if saved.ServerAddress != "" && server != saved.ServerAddress {
		return session.Keys{}, fmt.Errorf("logged in to %s, run gophkeeper logout first", saved.ServerAddress)
	}
	ca := cmp.Or(cfg.CA, flags.ca, saved.CAPath)
	if ca == "" {
		return session.Keys{}, errNoCA
	}
	// The next commands may run in another directory.
	if ca, err = filepath.Abs(ca); err != nil {
		return session.Keys{}, err
	}

	var password []byte
	if register {
		password, err = readNewPassword(cmd, passwordPrompt, repeatPasswordPrompt)
	} else {
		password, err = readPassword(cmd, passwordPrompt)
	}
	if err != nil {
		return session.Keys{}, err
	}
	defer clear(password)

	client, err := a.dial(server, ca)
	if err != nil {
		return session.Keys{}, err
	}
	defer client.Close()

	var salt []byte
	if register {
		salt = vaultcrypto.NewSalt()
	} else if salt, err = client.GetSalt(ctx, login); err != nil {
		return session.Keys{}, err
	}
	wrapKey, loginKey, err := vaultcrypto.DeriveKeys(password, salt)
	if err != nil {
		return session.Keys{}, err
	}
	if register {
		envelope := vaultcrypto.SealEnvelope(wrapKey, vaultcrypto.NewDataKey())
		if err := client.Register(ctx, login, salt, loginKey, envelope); err != nil {
			return session.Keys{}, err
		}
	}
	keys, envelope, err := signIn(ctx, client, login, wrapKey, loginKey)
	if err != nil {
		return session.Keys{}, err
	}

	err = store.SaveState(ctx, storage.State{
		ServerAddress: server,
		CAPath:        ca,
		Login:         login,
		Salt:          salt,
		Envelope:      envelope,
		Token:         client.Token(),
		LastRevision:  saved.LastRevision,
	})
	if err != nil {
		return session.Keys{}, err
	}
	return keys, nil
}

// syncAfterLogin syncs the records with the keys of the new session and
// prints the result to stderr, so that --raw still prints only the key. A
// failed sync does not fail the login: the session is already started.
func syncAfterLogin(cmd *cobra.Command, a app, keys session.Keys) {
	w := cmd.ErrOrStderr()
	res, err := loginSync(cmd.Context(), a, keys)
	if err != nil {
		fmt.Fprintf(w, "Logged in, but sync failed: %v\nRun gophkeeper sync to try again.\n", err)
		return
	}
	fmt.Fprintf(w, syncReport, res.Pushed, res.Pulled, res.Conflicts)
}

// loginSync syncs the records of the saved state with keys. The session key
// is not in the environment yet, so the vault is opened with keys.
func loginSync(ctx context.Context, a app, keys session.Keys) (vaultsync.Result, error) {
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
	v := &vault{app: a, cfg: cfg, store: store, state: st, keys: keys}
	return v.sync(ctx)
}
