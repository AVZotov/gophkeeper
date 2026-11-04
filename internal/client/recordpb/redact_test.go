package recordpb

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedacted(t *testing.T) {
	const secret = "secret-value"
	credentials := Credentials_builder{Login: secret, Password: secret}.Build()
	text := Text_builder{Content: secret}.Build()
	file := File_builder{Filename: secret, Content: []byte(secret)}.Build()
	card := Card_builder{Number: secret, Holder: secret, Cvv: secret}.Build()
	tests := []struct {
		name string
		msg  any
	}{
		{"record", Record_builder{Name: secret, Metadata: secret, Credentials: credentials}.Build()},
		{"credentials", credentials},
		{"text", text},
		{"file", file},
		{"card", card},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", "value", tt.msg)

			assert.Contains(t, buf.String(), `"value":"[REDACTED]"`)
			assert.NotContains(t, buf.String(), secret)
		})
	}
}
