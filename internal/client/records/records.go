// Package records checks, encrypts and decrypts the content of records. A
// record is a [recordpb.Record], marshaled and encrypted with the data key
// for its ID.
package records

import (
	"errors"
	"fmt"
	"strings"
	"uuid"

	"google.golang.org/protobuf/proto"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

// Limits of the record fields, in bytes. A record with a file of
// [MaxFileSize] and every field at its limit still fits into
// [pb.MaxCiphertextSize].
const (
	MaxNameSize     = 1 << 10
	MaxMetadataSize = 32 << 10
	MaxFilenameSize = 1 << 10
	MaxFileSize     = pb.MaxFileSize
	MaxTextSize     = pb.MaxFileSize
)

// Types of records, as the user names them.
const (
	TypeLogin = "login"
	TypeText  = "text"
	TypeFile  = "file"
	TypeCard  = "card"
)

// Limits of the card expiry.
const (
	minMonth = 1
	maxMonth = 12
)

var (
	// ErrInvalid means a record field breaks a rule.
	ErrInvalid = errors.New("invalid record")
	// ErrTooLarge means the record does not fit into the ciphertext limit.
	ErrTooLarge = errors.New("record is too large")
)

// Type returns the type of r, or "" if r has no data.
func Type(r *recordpb.Record) string {
	switch r.WhichData() {
	case recordpb.Record_Credentials_case:
		return TypeLogin
	case recordpb.Record_Text_case:
		return TypeText
	case recordpb.Record_File_case:
		return TypeFile
	case recordpb.Record_Card_case:
		return TypeCard
	}
	return ""
}

// Validate checks the fields of r entered by the user: the name is set, the
// fields fit into their limits, a card number has only digits and the
// expiry month is valid. Returns [ErrInvalid] listing the failed rules.
func Validate(r *recordpb.Record) error {
	var errs []error
	check := func(failed bool, format string, args ...any) {
		if failed {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(r.GetName() == "", "name is empty")
	check(len(r.GetName()) > MaxNameSize, "name is longer than %d bytes", MaxNameSize)
	check(len(r.GetMetadata()) > MaxMetadataSize, "metadata is longer than %d bytes", MaxMetadataSize)
	switch r.WhichData() {
	case recordpb.Record_Text_case:
		check(len(r.GetText().GetContent()) > MaxTextSize, "text is longer than %d bytes", MaxTextSize)
	case recordpb.Record_File_case:
		f := r.GetFile()
		check(f.GetFilename() == "", "file name is empty")
		check(len(f.GetFilename()) > MaxFilenameSize, "file name is longer than %d bytes", MaxFilenameSize)
		check(len(f.GetContent()) > MaxFileSize, "file is larger than %d bytes", MaxFileSize)
	case recordpb.Record_Card_case:
		c := r.GetCard()
		check(!onlyDigits(c.GetNumber()), "card number must be digits only")
		check(c.GetExpiryMonth() < minMonth || c.GetExpiryMonth() > maxMonth, "expiry month must be 1-12")
	case recordpb.Record_Data_not_set_case:
		errs = append(errs, errors.New("record has no data"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(errs...))
	}
	return nil
}

// Seal marshals r and encrypts it with the key for the record ID. It does
// not run [Validate]. Returns [ErrTooLarge] if the ciphertext would not fit
// into [pb.MaxCiphertextSize].
func Seal(key vaultcrypto.DataKey, id uuid.UUID, r *recordpb.Record) ([]byte, error) {
	plain, err := proto.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal record: %w", err)
	}
	if len(plain)+vaultcrypto.Overhead > pb.MaxCiphertextSize {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, len(plain), pb.MaxCiphertextSize-vaultcrypto.Overhead)
	}
	return vaultcrypto.EncryptRecord(key, id, plain), nil
}

// Open decrypts the record with the given ID sealed by [Seal]. Returns
// [vaultcrypto.ErrCorrupted] if the ciphertext does not open and an error
// if the content is malformed.
func Open(key vaultcrypto.DataKey, id uuid.UUID, ciphertext []byte) (*recordpb.Record, error) {
	plain, err := vaultcrypto.DecryptRecord(key, id, ciphertext)
	if err != nil {
		return nil, err
	}
	r := recordpb.Record_builder{}.Build()
	if err := proto.Unmarshal(plain, r); err != nil {
		return nil, fmt.Errorf("unmarshal record %s: %w", id, err)
	}
	return r, nil
}

// onlyDigits reports whether s is not empty and has only ASCII digits.
func onlyDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}
