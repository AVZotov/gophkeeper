package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AVZotov/gophkeeper/internal/server/auth"
)

const testSecretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// configEnv lists the variables the server reads.
var configEnv = []string{"ADDRESS", "DATABASE_DSN", "TLS_CERT", "TLS_KEY", "SERVER_SECRET"}

// clearEnv unsets the server variables for the test, so the developer's
// environment does not leak into it.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range configEnv {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}

func mustHexSecret(t *testing.T, s string) hexSecret {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want config
	}{
		{
			name: "defaults",
			args: []string{"-d", "flag-dsn"},
			env:  map[string]string{"SERVER_SECRET": testSecretHex},
			want: config{
				Address:     defaultAddress,
				DatabaseDSN: "flag-dsn",
				TLSCert:     defaultTLSCert,
				TLSKey:      defaultTLSKey,
				Secret:      mustHexSecret(t, testSecretHex),
			},
		},
		{
			name: "flags",
			args: []string{"-a", "flag-addr", "-d", "flag-dsn", "-tls-cert", "flag.crt", "-tls-key", "flag.key"},
			env:  map[string]string{"SERVER_SECRET": testSecretHex},
			want: config{
				Address:     "flag-addr",
				DatabaseDSN: "flag-dsn",
				TLSCert:     "flag.crt",
				TLSKey:      "flag.key",
				Secret:      mustHexSecret(t, testSecretHex),
			},
		},
		{
			name: "environment overrides flags",
			args: []string{"-a", "flag-addr", "-d", "flag-dsn", "-tls-cert", "flag.crt", "-tls-key", "flag.key"},
			env: map[string]string{
				"ADDRESS":       "env-addr",
				"DATABASE_DSN":  "env-dsn",
				"TLS_CERT":      "env.crt",
				"TLS_KEY":       "env.key",
				"SERVER_SECRET": testSecretHex,
			},
			want: config{
				Address:     "env-addr",
				DatabaseDSN: "env-dsn",
				TLSCert:     "env.crt",
				TLSKey:      "env.key",
				Secret:      mustHexSecret(t, testSecretHex),
			},
		},
		{
			name: "spaces around the secret",
			args: []string{"-d", "flag-dsn"},
			env:  map[string]string{"SERVER_SECRET": " \t" + testSecretHex + "\n"},
			want: config{
				Address:     defaultAddress,
				DatabaseDSN: "flag-dsn",
				TLSCert:     defaultTLSCert,
				TLSKey:      defaultTLSKey,
				Secret:      mustHexSecret(t, testSecretHex),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := loadConfig(tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		secret  string
		wantErr error
	}{
		{name: "no DSN", secret: testSecretHex, wantErr: errNoDSN},
		{name: "no secret", args: []string{"-d", "dsn"}, wantErr: auth.ErrSecretSize},
		{name: "short secret", args: []string{"-d", "dsn"}, secret: testSecretHex[2:], wantErr: auth.ErrSecretSize},
		{name: "secret not hex", args: []string{"-d", "dsn"}, secret: "secret-word"},
		{name: "secret flag", args: []string{"-d", "dsn", "-secret", testSecretHex}, secret: testSecretHex},
		{name: "help", args: []string{"-h"}, wantErr: flag.ErrHelp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			if tt.secret != "" {
				t.Setenv("SERVER_SECRET", tt.secret)
			}
			_, err := loadConfig(tt.args)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.NotContains(t, err.Error(), "secret-word", "the error must not quote the secret")
		})
	}
}

func TestHexSecretRedacted(t *testing.T) {
	cfg := config{DatabaseDSN: "dsn", Secret: mustHexSecret(t, testSecretHex)}

	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("test", "secret", cfg.Secret, "config", cfg)
	outputs := []string{
		logs.String(),
		fmt.Sprintf("%v %+v %s %x %q", cfg, cfg, cfg.Secret, cfg.Secret, cfg.Secret),
	}
	for _, out := range outputs {
		assert.Contains(t, out, redacted)
		assert.NotContains(t, out, testSecretHex)
		assert.NotContains(t, out, "AAECAwQF", "base64 of the secret")
	}
}
