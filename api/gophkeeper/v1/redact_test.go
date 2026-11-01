package gophkeeperv1

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedacted(t *testing.T) {
	secret := []byte("secret-bytes")
	tests := []struct {
		name string
		msg  any
	}{
		{"register", RegisterRequest_builder{Login: "alice", Salt: secret, LoginKey: secret, Envelope: secret}.Build()},
		{"login", LoginRequest_builder{Login: "alice", LoginKey: secret}.Build()},
		{"login response", LoginResponse_builder{Token: string(secret), Envelope: secret}.Build()},
		{"change password", ChangePasswordRequest_builder{OldLoginKey: secret, NewSalt: secret, NewLoginKey: secret, NewEnvelope: secret}.Build()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", "value", tt.msg)

			assert.Contains(t, buf.String(), `"value":"[REDACTED]"`)
			assert.NotContains(t, buf.String(), string(secret))
		})
	}
}
