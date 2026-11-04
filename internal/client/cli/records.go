package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"uuid"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/records"
)

// Flags of the record fields.
const (
	flagName     = "name"
	flagMeta     = "meta"
	flagLogin    = "login"
	flagPassword = "password"
	flagText     = "text"
	flagFile     = "file"
	flagNumber   = "number"
	flagHolder   = "holder"
	flagExpiry   = "expiry"
	flagCVV      = "cvv"
)

// askValue is the flag value that asks for the password or the CVV without
// echo, or reads the text from the input. It lets edit ask for them; add
// asks when the flag is not given.
const askValue = "-"

// Prompts for the secret fields.
const (
	recordPasswordPrompt = "Password: "
	cvvPrompt            = "CVV: "
	textPrompt           = "Type the text, then press Ctrl+D (Ctrl+Z and Enter on Windows):\n"
)

// expiryCentury turns the two-digit year of a card expiry into a full one.
const expiryCentury = 2000

// expiryPartSize is the number of digits of the month and of the year in
// MM/YY.
const expiryPartSize = 2

// mebibyte is the unit of the file size limit in the help.
const mebibyte = 1 << 20

// idHelp tells which ID the commands that take a record ID accept.
const idHelp = "ID is the record ID or its beginning, as shown by list."

// historyWarning ends the help of the flags with secrets.
const historyWarning = "; a value given here stays in the shell history"

var errNothingToChange = errors.New("nothing to change: give the fields to change as flags")

// flagUsage is the help of the record field flags.
var flagUsage = map[string]string{
	flagName:     "record name",
	flagMeta:     "free-form metadata: website, bank, notes",
	flagLogin:    "login, user name or email",
	flagPassword: "password; asked for without echo if not given or \"-\"" + historyWarning,
	flagText:     "text; read from the input if not given or \"-\"",
	flagFile:     "path of the file to store",
	flagNumber:   "card number, digits only",
	flagHolder:   "cardholder name",
	flagExpiry:   "expiry date, MM/YY",
	flagCVV:      "card verification code; asked for without echo if not given or \"-\"" + historyWarning,
}

// recordKind is a record type as the commands see it.
type recordKind struct {
	name  string
	short string
	// flags are the flags of the fields of the type; required ones must be
	// given to add a record.
	flags, required []string
	// empty returns a record of the type with no fields set.
	empty func() *recordpb.Record
}

// kinds are the record types, in the order of the add subcommands.
var kinds = []recordKind{
	{
		name:  records.TypeLogin,
		short: "Add a login and password",
		flags: []string{flagLogin, flagPassword},
		empty: func() *recordpb.Record {
			return recordpb.Record_builder{Credentials: recordpb.Credentials_builder{}.Build()}.Build()
		},
	},
	{
		name:  records.TypeText,
		short: "Add a text",
		flags: []string{flagText},
		empty: func() *recordpb.Record { return recordpb.Record_builder{Text: recordpb.Text_builder{}.Build()}.Build() },
	},
	{
		name:     records.TypeFile,
		short:    "Add a file of up to " + strconv.Itoa(records.MaxFileSize/mebibyte) + " MiB",
		flags:    []string{flagFile},
		required: []string{flagFile},
		empty:    func() *recordpb.Record { return recordpb.Record_builder{File: recordpb.File_builder{}.Build()}.Build() },
	},
	{
		name:     records.TypeCard,
		short:    "Add a bank card",
		flags:    []string{flagNumber, flagHolder, flagExpiry, flagCVV},
		required: []string{flagNumber, flagExpiry},
		empty:    func() *recordpb.Record { return recordpb.Record_builder{Card: recordpb.Card_builder{}.Build()}.Build() },
	},
}

// addFlags adds the named record field flags to cmd.
func addFlags(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		cmd.Flags().String(name, "", flagUsage[name])
	}
}

// newAddCmd returns the add command with a subcommand for every record type.
func newAddCmd(a app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a record: login, text, file or card",
		Long: "Add saves a new record locally and syncs it with the server. If the server is" +
			" unavailable, the record syncs later.",
	}
	for _, k := range kinds {
		cmd.AddCommand(newAddKindCmd(a, k))
	}
	return cmd
}

// newAddKindCmd returns the subcommand of add for the record type.
func newAddKindCmd(a app, k recordKind) *cobra.Command {
	cmd := &cobra.Command{
		Use:   k.name,
		Short: k.short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := a.openVault(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()

			rec := k.empty()
			if err := applyFlags(cmd, rec, true); err != nil {
				return err
			}
			id := uuid.New()
			if err := v.save(cmd, id, rec); err != nil {
				return err
			}
			return v.saved(cmd, "Added", id)
		},
	}
	addFlags(cmd, append([]string{flagName, flagMeta}, k.flags...)...)
	for _, name := range append([]string{flagName}, k.required...) {
		cmd.MarkFlagRequired(name)
	}
	return cmd
}

// newEditCmd returns the edit command.
func newEditCmd(a app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit ID",
		Short: "Change the fields of a record given as flags",
		Long: "Edit changes only the fields given as flags. " + idHelp + " --password - and" +
			" --cvv - ask for the new value without echo, --text - reads the text from the input.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()

			stored, rec, err := v.find(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := applyFlags(cmd, rec, false); err != nil {
				return err
			}
			if err := v.save(cmd, stored.ID, rec); err != nil {
				return err
			}
			return v.saved(cmd, "Updated", stored.ID)
		},
	}
	addFlags(cmd, flagName, flagMeta)
	for _, k := range kinds {
		addFlags(cmd, k.flags...)
	}
	return cmd
}

// newDeleteCmd returns the delete command.
func newDeleteCmd(a app) *cobra.Command {
	return &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a record",
		Long:  "Delete deletes the record on all devices after sync. " + idHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := a.openVault(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()

			// A record that does not decrypt can still be deleted.
			stored, err := v.match(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := v.store.SaveLocal(cmd.Context(), stored.ID, true, nil); err != nil {
				return err
			}
			return v.saved(cmd, "Deleted", stored.ID)
		},
	}
}

// save checks rec, encrypts it and saves it as a local change.
func (v *vault) save(cmd *cobra.Command, id uuid.UUID, rec *recordpb.Record) error {
	if err := records.Validate(rec); err != nil {
		return err
	}
	ciphertext, err := records.Seal(v.keys.Data, id, rec)
	if err != nil {
		return err
	}
	return v.store.SaveLocal(cmd.Context(), id, false, ciphertext)
}

// saved tells the user that the record was changed, as verb says, and
// syncs the change.
func (v *vault) saved(cmd *cobra.Command, verb string, id uuid.UUID) error {
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s record %s.\n", verb, shortID(id)); err != nil {
		return err
	}
	return v.syncChange(cmd)
}

// applyFlags sets the fields of rec given as flags. When adding, the
// fields that can be asked for and are not given are asked for. Returns an
// error if a flag does not belong to the type of rec, no flag is given when
// editing or a value is malformed.
func applyFlags(cmd *cobra.Command, rec *recordpb.Record, adding bool) error {
	recordType := records.Type(rec)
	given := cmd.Flags().Changed
	for _, k := range kinds {
		if k.name == recordType {
			continue
		}
		for _, name := range k.flags {
			if given(name) {
				return fmt.Errorf("--%s does not apply to a %s record", name, recordType)
			}
		}
	}
	if !adding && cmd.Flags().NFlag() == 0 {
		return errNothingToChange
	}
	value := func(name string) string {
		v, _ := cmd.Flags().GetString(name)
		return v
	}

	if given(flagName) {
		rec.SetName(value(flagName))
	}
	if given(flagMeta) {
		rec.SetMetadata(value(flagMeta))
	}
	switch recordType {
	case records.TypeLogin:
		c := rec.GetCredentials()
		if given(flagLogin) {
			c.SetLogin(value(flagLogin))
		}
		if given(flagPassword) || adding {
			password, err := secret(cmd, value(flagPassword), recordPasswordPrompt)
			if err != nil {
				return err
			}
			c.SetPassword(password)
		}
	case records.TypeText:
		if given(flagText) || adding {
			text, err := readText(cmd, value(flagText))
			if err != nil {
				return err
			}
			rec.GetText().SetContent(text)
		}
	case records.TypeFile:
		if given(flagFile) {
			file, err := readFile(value(flagFile))
			if err != nil {
				return err
			}
			rec.SetFile(file)
		}
	case records.TypeCard:
		c := rec.GetCard()
		if given(flagNumber) {
			c.SetNumber(value(flagNumber))
		}
		if given(flagHolder) {
			c.SetHolder(value(flagHolder))
		}
		if given(flagExpiry) {
			month, year, err := parseExpiry(value(flagExpiry))
			if err != nil {
				return err
			}
			c.SetExpiryMonth(month)
			c.SetExpiryYear(year)
		}
		if given(flagCVV) || adding {
			cvv, err := secret(cmd, value(flagCVV), cvvPrompt)
			if err != nil {
				return err
			}
			c.SetCvv(cvv)
		}
	}
	return nil
}

// secret returns value, or asks for the secret without echo if value is
// empty or [askValue].
func secret(cmd *cobra.Command, value, prompt string) (string, error) {
	if value != "" && value != askValue {
		return value, nil
	}
	b, err := readPassword(cmd, prompt)
	return string(b), err
}

// readText returns value, or reads the text from the input up to its end if
// value is empty or [askValue]. Returns an error if the text is longer than
// [records.MaxTextSize].
func readText(cmd *cobra.Command, value string) (string, error) {
	if value != "" && value != askValue {
		return value, nil
	}
	read := func() ([]byte, error) { return io.ReadAll(io.LimitReader(cmd.InOrStdin(), records.MaxTextSize+1)) }
	var (
		b   []byte
		err error
	)
	if fd, ok := terminal(cmd); ok {
		fmt.Fprint(cmd.ErrOrStderr(), textPrompt)
		b, err = readTerminal(cmd.Context(), fd, read)
	} else {
		b, err = read()
	}
	if err != nil {
		return "", fmt.Errorf("read text: %w", err)
	}
	if len(b) > records.MaxTextSize {
		return "", fmt.Errorf("%w: text is longer than %d bytes", records.ErrTooLarge, records.MaxTextSize)
	}
	return string(b), nil
}

// readFile reads the file at path for a record. The size is checked before
// the file is read. Returns [records.ErrTooLarge] if the file is larger than
// [records.MaxFileSize].
func readFile(path string) (*recordpb.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > records.MaxFileSize {
		return nil, fmt.Errorf("%w: %s is %d bytes, the limit is %d", records.ErrTooLarge, path, info.Size(), records.MaxFileSize)
	}
	// The file may grow after Stat.
	content, err := io.ReadAll(io.LimitReader(f, records.MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > records.MaxFileSize {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", records.ErrTooLarge, path, records.MaxFileSize)
	}
	return recordpb.File_builder{Filename: filepath.Base(path), Content: content}.Build(), nil
}

// parseExpiry parses a card expiry in the MM/YY form. Returns
// [records.ErrInvalid] if it is malformed; the month is checked by
// [records.Validate].
func parseExpiry(s string) (month, year int32, err error) {
	mm, yy, _ := strings.Cut(s, "/")
	m, okM := twoDigits(mm)
	y, okY := twoDigits(yy)
	if !okM || !okY {
		return 0, 0, fmt.Errorf("%w: expiry must be MM/YY, got %q", records.ErrInvalid, s)
	}
	return m, expiryCentury + y, nil
}

// twoDigits returns the number written in s if s is exactly
// [expiryPartSize] ASCII digits.
func twoDigits(s string) (int32, bool) {
	if len(s) != expiryPartSize {
		return 0, false
	}
	// ParseUint, unlike Atoi, does not take a sign.
	n, err := strconv.ParseUint(s, 10, 0)
	return int32(n), err == nil
}
