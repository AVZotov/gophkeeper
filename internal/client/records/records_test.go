package records

import (
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
)

func login() *recordpb.Record {
	return recordpb.Record_builder{
		Name:        "mail",
		Credentials: recordpb.Credentials_builder{Login: "alice", Password: "secret"}.Build(),
	}.Build()
}

func text(content string) *recordpb.Record {
	return recordpb.Record_builder{Name: "note", Text: recordpb.Text_builder{Content: content}.Build()}.Build()
}

func file(name string, size int) *recordpb.Record {
	return recordpb.Record_builder{
		Name: "doc",
		File: recordpb.File_builder{Filename: name, Content: make([]byte, size)}.Build(),
	}.Build()
}

func card(number string, month int32) *recordpb.Record {
	return recordpb.Record_builder{
		Name: "visa",
		Card: recordpb.Card_builder{Number: number, ExpiryMonth: month, ExpiryYear: 2029, Cvv: "123"}.Build(),
	}.Build()
}

func TestType(t *testing.T) {
	tests := []struct {
		rec  *recordpb.Record
		want string
	}{
		{login(), TypeLogin},
		{text("x"), TypeText},
		{file("a.txt", 1), TypeFile},
		{card("4111", 1), TypeCard},
		{recordpb.Record_builder{}.Build(), ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, Type(tt.rec))
	}
}

func TestValidate(t *testing.T) {
	with := func(r *recordpb.Record, change func(*recordpb.Record)) *recordpb.Record {
		change(r)
		return r
	}
	valid := []*recordpb.Record{
		login(),
		text(strings.Repeat("x", MaxTextSize)),
		file("a.txt", MaxFileSize),
		card("4111111111111111", 12),
		with(login(), func(r *recordpb.Record) { r.SetName(strings.Repeat("n", MaxNameSize)) }),
		with(login(), func(r *recordpb.Record) { r.SetMetadata(strings.Repeat("m", MaxMetadataSize)) }),
	}
	for _, r := range valid {
		assert.NoError(t, Validate(r), Type(r))
	}

	tests := []struct {
		name    string
		rec     *recordpb.Record
		wantMsg string
	}{
		{"empty name", with(login(), func(r *recordpb.Record) { r.SetName("") }), "name is empty"},
		{"long name", with(login(), func(r *recordpb.Record) { r.SetName(strings.Repeat("n", MaxNameSize+1)) }), "name is longer"},
		{"long metadata", with(login(), func(r *recordpb.Record) { r.SetMetadata(strings.Repeat("m", MaxMetadataSize+1)) }), "metadata is longer"},
		{"long text", text(strings.Repeat("x", MaxTextSize+1)), "text is longer"},
		{"empty file name", file("", 1), "file name is empty"},
		{"long file name", file(strings.Repeat("f", MaxFilenameSize+1), 1), "file name is longer"},
		{"large file", file("a.txt", MaxFileSize+1), "file is larger"},
		{"card number with letters", card("4111x", 1), "digits only"},
		{"card number with spaces", card("4111 1111", 1), "digits only"},
		{"empty card number", card("", 1), "digits only"},
		{"month 0", card("4111", 0), "month"},
		{"month 13", card("4111", 13), "month"},
		{"no data", recordpb.Record_builder{Name: "x"}.Build(), "no data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.rec)
			assert.ErrorIs(t, err, ErrInvalid)
			assert.ErrorContains(t, err, tt.wantMsg)
		})
	}
}

func TestSealOpen(t *testing.T) {
	key := vaultcrypto.NewDataKey()
	id := uuid.New()
	for _, rec := range []*recordpb.Record{login(), text("hello"), file("a.txt", 10), card("4111", 7)} {
		ciphertext, err := Seal(key, id, rec)
		require.NoError(t, err)

		got, err := Open(key, id, ciphertext)
		require.NoError(t, err)
		assert.True(t, proto.Equal(rec, got), Type(rec))
	}
}

// TestLargestRecordFits fills every field of a file record up to its limit.
func TestLargestRecordFits(t *testing.T) {
	rec := file(strings.Repeat("f", MaxFilenameSize), MaxFileSize)
	rec.SetName(strings.Repeat("n", MaxNameSize))
	rec.SetMetadata(strings.Repeat("m", MaxMetadataSize))
	require.NoError(t, Validate(rec))

	ciphertext, err := Seal(vaultcrypto.NewDataKey(), uuid.New(), rec)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(ciphertext), pb.MaxCiphertextSize)
}

func TestSealTooLarge(t *testing.T) {
	_, err := Seal(vaultcrypto.NewDataKey(), uuid.New(), text(strings.Repeat("x", pb.MaxCiphertextSize)))
	assert.ErrorIs(t, err, ErrTooLarge)
}

func TestOpenFails(t *testing.T) {
	key := vaultcrypto.NewDataKey()
	id := uuid.New()
	ciphertext, err := Seal(key, id, login())
	require.NoError(t, err)

	_, err = Open(vaultcrypto.NewDataKey(), id, ciphertext)
	assert.ErrorIs(t, err, vaultcrypto.ErrCorrupted, "other key")
	_, err = Open(key, uuid.New(), ciphertext)
	assert.ErrorIs(t, err, vaultcrypto.ErrCorrupted, "other ID")

	_, err = Open(key, id, vaultcrypto.EncryptRecord(key, id, []byte{0xff}))
	assert.ErrorContains(t, err, "unmarshal record", "not a record")
}
