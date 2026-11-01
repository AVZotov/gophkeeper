package cli

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/records"
	"github.com/AVZotov/gophkeeper/internal/client/vaultsync"
)

// fileMode keeps a file saved by show readable only by its owner.
const fileMode = 0o600

// columnPadding separates the columns printed by list and show.
const columnPadding = 2

// expiryYears turns the full year of a card expiry into two digits.
const expiryYears = 100

var errOutNotFile = errors.New("--out applies only to a file record")

// newListCmd returns the list command.
func newListCmd(a app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the records: ID, type and name",
		Long: "List shows the local records, without secrets, by name. It works offline: run gophkeeper sync" +
			" to get the changes from other devices. A copy made by a sync conflict has \"" +
			vaultsync.ConflictSuffix + "\" in its name.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := a.openVault(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()

			stored, err := v.store.List(cmd.Context())
			if err != nil {
				return err
			}
			type row struct{ id, recordType, name string }
			rows := make([]row, 0, len(stored))
			for _, r := range stored {
				recordType, name := v.describe(r)
				rows = append(rows, row{r.ID.String(), recordType, name})
			}
			slices.SortFunc(rows, func(a, b row) int {
				return cmp.Or(
					cmp.Compare(strings.ToLower(a.name), strings.ToLower(b.name)),
					cmp.Compare(a.name, b.name),
					cmp.Compare(a.id, b.id),
				)
			})

			w := newTable(cmd.OutOrStdout())
			fmt.Fprintln(w, "ID\tTYPE\tNAME")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.id, r.recordType, r.name)
			}
			return w.Flush()
		},
	}
}

// newShowCmd returns the show command.
func newShowCmd(a app) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "show ID",
		Short: "Show a record with its secrets",
		Long: "Show prints the record, its password and CVV included. ID is the record ID or its" +
			" unique prefix. The content of a file is saved with --out. Show works offline.",
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
			if out != "" && !rec.HasFile() {
				return errOutNotFile
			}
			w := newTable(cmd.OutOrStdout())
			fmt.Fprintf(w, "ID:\t%s\n", stored.ID)
			printRecord(w, rec)
			if err := w.Flush(); err != nil {
				return err
			}
			return showContent(cmd, rec, out)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "save the content of a file record to this path")
	return cmd
}

// printRecord prints the fields of rec, except a text and the content of a
// file, as a table.
func printRecord(w io.Writer, rec *recordpb.Record) {
	fmt.Fprintf(w, "Type:\t%s\n", records.Type(rec))
	fmt.Fprintf(w, "Name:\t%s\n", rec.GetName())
	if rec.GetMetadata() != "" {
		fmt.Fprintf(w, "Metadata:\t%s\n", rec.GetMetadata())
	}
	switch rec.WhichData() {
	case recordpb.Record_Credentials_case:
		c := rec.GetCredentials()
		fmt.Fprintf(w, "Login:\t%s\n", c.GetLogin())
		fmt.Fprintf(w, "Password:\t%s\n", c.GetPassword())
	case recordpb.Record_File_case:
		f := rec.GetFile()
		fmt.Fprintf(w, "File:\t%s\n", f.GetFilename())
		fmt.Fprintf(w, "Size:\t%d bytes\n", len(f.GetContent()))
	case recordpb.Record_Card_case:
		c := rec.GetCard()
		fmt.Fprintf(w, "Number:\t%s\n", c.GetNumber())
		fmt.Fprintf(w, "Holder:\t%s\n", c.GetHolder())
		fmt.Fprintf(w, "Expiry:\t%02d/%02d\n", c.GetExpiryMonth(), c.GetExpiryYear()%expiryYears)
		fmt.Fprintf(w, "CVV:\t%s\n", c.GetCvv())
	}
}

// showContent prints a text after the table, or saves the content of a file
// to out. The file is not overwritten if it exists.
func showContent(cmd *cobra.Command, rec *recordpb.Record, out string) error {
	switch {
	case rec.HasText():
		// A text read from the input usually ends with a line break already.
		text := rec.GetText().GetContent()
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		_, err := fmt.Fprint(cmd.OutOrStdout(), "\n"+text)
		return err
	case rec.HasFile() && out == "":
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "\nRun show with --out PATH to save the file.")
		return err
	case rec.HasFile():
		content := rec.GetFile().GetContent()
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
		if err != nil {
			return err
		}
		if _, err := f.Write(content); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "\nSaved %d bytes to %s.\n", len(content), out)
		return err
	}
	return nil
}

// newTable returns a writer that aligns tab-separated columns.
func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, columnPadding, ' ', 0)
}
