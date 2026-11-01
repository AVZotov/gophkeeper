package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Prompts for the master password.
const (
	passwordPrompt          = "Master password: "
	repeatPasswordPrompt    = "Repeat master password: "
	currentPasswordPrompt   = "Current master password: "
	newPasswordPrompt       = "New master password: "
	repeatNewPasswordPrompt = "Repeat new master password: "
)

var (
	errPasswordMismatch = errors.New("passwords do not match")
	errEmptyPassword    = errors.New("password is empty")
)

// readPassword prints the prompt to the error output of cmd and reads the
// password from its input. From a terminal the password is read without
// echo; otherwise it is the next line of the input, so a script can pass it
// through a pipe.
func readPassword(cmd *cobra.Command, prompt string) ([]byte, error) {
	w := cmd.ErrOrStderr()
	fmt.Fprint(w, prompt)
	if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		password, err := term.ReadPassword(int(f.Fd()))
		// The Enter key was not echoed either.
		fmt.Fprintln(w)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		return password, nil
	}
	return readLine(cmd.InOrStdin())
}

// readNewPassword reads a new password twice, with prompt and then with
// repeatPrompt: a typo in it would lock the user out for good. Returns an
// error if the two differ or the password is empty.
func readNewPassword(cmd *cobra.Command, prompt, repeatPrompt string) ([]byte, error) {
	password, err := readPassword(cmd, prompt)
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, errEmptyPassword
	}
	repeated, err := readPassword(cmd, repeatPrompt)
	defer clear(repeated)
	if err != nil {
		clear(password)
		return nil, err
	}
	if !bytes.Equal(password, repeated) {
		clear(password)
		return nil, errPasswordMismatch
	}
	return password, nil
}

// readLine reads r up to a line break, one byte at a time: a buffered reader
// would take the input meant for the next prompt too.
func readLine(r io.Reader) ([]byte, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				return bytes.TrimSuffix(line, []byte("\r")), nil
			}
			line = append(line, b[0])
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return bytes.TrimSuffix(line, []byte("\r")), nil
		}
		if err != nil {
			clear(line)
			return nil, fmt.Errorf("read password: %w", err)
		}
	}
}
