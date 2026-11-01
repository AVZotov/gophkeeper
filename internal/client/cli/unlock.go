package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

const passwordPrompt = "Master password: "

// unlockHint tells how to set the session key. The verbs are the session
// lifetime and the key, as indexed arguments.
const unlockHint = `Your vault is unlocked. The session expires in %[1]v.

Set the session key in this terminal so that commands can use it:

  bash, zsh:   export ` + session.EnvVar + `="%[2]s"
  PowerShell:  $env:` + session.EnvVar + `="%[2]s"
  cmd:         set "` + session.EnvVar + `=%[2]s"

Or unlock and set the key at once in bash or zsh:

  export ` + session.EnvVar + `=$(gophkeeper unlock --raw)
`

// newUnlockCmd returns the unlock command. Like bw unlock of Bitwarden CLI,
// it opens the envelope with the master password, starts a session and
// prints the session key.
func newUnlockCmd(f files) *cobra.Command {
	var raw bool
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault and print a session key",
		Long: "Unlock asks for the master password, unlocks the vault for " + session.TTL.String() +
			" and prints a session key. Commands take the key from " + session.EnvVar +
			". A new unlock ends the previous session.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, err := unlock(cmd, f)
			if err != nil {
				return err
			}
			if raw {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), key)
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), unlockHint, session.TTL, key)
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&raw, "raw", false, "print only the session key")
	return cmd
}

// unlock derives the keys from the password and the saved salt and
// envelope, starts a session and returns its key. Returns an error if the
// user has not logged in or the password is wrong.
func unlock(cmd *cobra.Command, f files) (string, error) {
	store, err := f.openStore(cmd.Context())
	if err != nil {
		return "", err
	}
	defer store.Close()

	st, err := store.State(cmd.Context())
	if errors.Is(err, storage.ErrNoState) {
		return "", fmt.Errorf("%w, run gophkeeper login first", err)
	}
	if err != nil {
		return "", err
	}

	password, err := readPassword(cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	wrapKey, loginKey, err := vaultcrypto.DeriveKeys(password, st.Salt)
	clear(password)
	if err != nil {
		return "", err
	}
	dataKey, err := vaultcrypto.OpenEnvelope(wrapKey, st.Envelope)
	if err != nil {
		return "", err
	}

	path, err := f.path(sessionFile)
	if err != nil {
		return "", err
	}
	return session.Unlock(path, session.Keys{Data: dataKey, Login: loginKey}, time.Now())
}

// readPassword prints the prompt to w and reads the password from r. From a
// terminal the password is read without echo; otherwise it is the first line
// of r, so a script can pass it through a pipe.
func readPassword(r io.Reader, w io.Writer) ([]byte, error) {
	fmt.Fprint(w, passwordPrompt)
	if f, ok := r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		password, err := term.ReadPassword(int(f.Fd()))
		// The Enter key was not echoed either.
		fmt.Fprintln(w)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		return password, nil
	}

	line, err := bufio.NewReader(r).ReadBytes('\n')
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return bytes.TrimRight(line, "\r\n"), nil
}
