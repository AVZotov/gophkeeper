package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/caarlos0/env/v11"

	"github.com/AVZotov/gophkeeper/internal/server/auth"
)

// Default configuration values. The certificate paths match the output of
// the certs task.
const (
	defaultAddress = "localhost:8443"
	defaultTLSCert = "certs/server.crt"
	defaultTLSKey  = "certs/server.key"
)

const redacted = "[REDACTED]"

var errNoDSN = errors.New("database DSN is required: set DATABASE_DSN or -d")

// config is the server configuration. Environment variables override flags,
// flags override defaults. The secret comes only from the environment: a
// flag would show it in the process list.
type config struct {
	Address     string    `env:"ADDRESS"`
	DatabaseDSN string    `env:"DATABASE_DSN"`
	TLSCert     string    `env:"TLS_CERT"`
	TLSKey      string    `env:"TLS_KEY"`
	Secret      hexSecret `env:"SERVER_SECRET"`
}

// hexSecret is the server secret, given in hex. fmt and slog print it as
// [REDACTED].
type hexSecret []byte

// UnmarshalText decodes the secret from hex, ignoring spaces and line breaks
// around it, as in a secret read from a file. The error does not quote the
// input, so it cannot leak part of the secret.
func (s *hexSecret) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(bytes.TrimSpace(text)))
	if err != nil {
		return errors.New("server secret must be hex")
	}
	*s = b
	return nil
}

// String hides the secret.
func (hexSecret) String() string { return redacted }

// Format hides the secret for every fmt verb.
func (hexSecret) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue hides the secret in slog output.
func (hexSecret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON hides the secret in JSON. slog uses it for a config logged as
// a whole: LogValue works only for top-level values.
func (hexSecret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// loadConfig reads the configuration from args and the environment. Returns
// [flag.ErrHelp] if help was asked for, [auth.ErrSecretSize] if the secret
// is missing or has the wrong size, and an error if a value is invalid or
// the DSN is missing.
func loadConfig(args []string) (config, error) {
	cfg := config{
		Address: defaultAddress,
		TLSCert: defaultTLSCert,
		TLSKey:  defaultTLSKey,
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&cfg.Address, "a", cfg.Address, "address to listen on (ADDRESS)")
	fs.StringVar(&cfg.DatabaseDSN, "d", cfg.DatabaseDSN, "PostgreSQL connection string (DATABASE_DSN)")
	fs.StringVar(&cfg.TLSCert, "tls-cert", cfg.TLSCert, "TLS certificate file (TLS_CERT)")
	fs.StringVar(&cfg.TLSKey, "tls-key", cfg.TLSKey, "TLS private key file (TLS_KEY)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage of server:")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "Environment:\n  SERVER_SECRET\n    \tserver secret, %d bytes in hex (required)\n", auth.SecretSize)
	}
	// Parse errors are returned and logged by the caller, so flag does not
	// print them itself; only help is printed.
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stderr)
			fs.Usage()
		}
		return config{}, err
	}
	if err := env.Parse(&cfg); err != nil {
		return config{}, fmt.Errorf("read environment: %w", err)
	}

	if cfg.DatabaseDSN == "" {
		return config{}, errNoDSN
	}
	if len(cfg.Secret) != auth.SecretSize {
		return config{}, fmt.Errorf("SERVER_SECRET: %w", auth.ErrSecretSize)
	}
	return cfg, nil
}
