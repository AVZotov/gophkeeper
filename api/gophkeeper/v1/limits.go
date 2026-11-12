package gophkeeperv1

// MaxFileSize is the largest file a record holds, in bytes.
const MaxFileSize = 10 << 20

// recordFieldsSize leaves room in a ciphertext for the name, the metadata
// and the file name of a record and for the encryption overhead.
const recordFieldsSize = 64 << 10

// MaxCiphertextSize is the largest record ciphertext, in bytes.
const MaxCiphertextSize = MaxFileSize + recordFieldsSize

// A Pull page has at most MaxPageRecords records, and their ciphertexts fit
// into MaxPageBytes, unless the first record alone is larger.
const (
	MaxPageRecords = 1000
	MaxPageBytes   = 4 << 20
)

// recordOverhead bounds the encoded size of a Record in a Pull page or of a
// PushRequest without the ciphertext bytes: the ID, the revision, the flag,
// field tags and lengths.
const recordOverhead = 64

// MaxMessageSize is the largest message, in bytes: a full Pull page or a
// Push with the largest ciphertext. The server and the client accept
// messages of this size.
const MaxMessageSize = max(MaxCiphertextSize, MaxPageBytes) + MaxPageRecords*recordOverhead
