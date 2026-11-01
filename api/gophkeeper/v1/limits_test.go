package gophkeeperv1

import (
	"math"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

// TestMaxMessageSize checks that the largest messages the limits allow fit
// into MaxMessageSize.
func TestMaxMessageSize(t *testing.T) {
	id := uuid.Max()
	record := func(ciphertextSize int) *Record {
		return Record_builder{
			Id:         id[:],
			Revision:   math.MaxInt64,
			Deleted:    true,
			Ciphertext: make([]byte, ciphertextSize),
		}.Build()
	}
	page := func(first, rest int) *PullResponse {
		records := []*Record{record(first)}
		for range MaxPageRecords - 1 {
			records = append(records, record(rest))
		}
		return PullResponse_builder{Records: records, HasMore: true}.Build()
	}

	tests := []struct {
		name string
		msg  proto.Message
	}{
		{"push", PushRequest_builder{
			Id:           id[:],
			BaseRevision: math.MaxInt64,
			Deleted:      true,
			Ciphertext:   make([]byte, MaxCiphertextSize),
		}.Build()},
		{"page of the largest record", page(MaxCiphertextSize, 0)},
		{"page of small records", page(MaxPageBytes/MaxPageRecords, MaxPageBytes/MaxPageRecords)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.LessOrEqual(t, proto.Size(tt.msg), MaxMessageSize)
		})
	}
}
