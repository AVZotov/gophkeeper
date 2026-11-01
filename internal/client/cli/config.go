package cli

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/caarlos0/env/v11"
	"github.com/spf13/cobra"
)

// envPrefix starts the names of the environment variables of the client.
const envPrefix = "GOPHKEEPER_"

// sessionEnv holds the session key; see config.Session.
const sessionEnv = envPrefix + "SESSION"

// defaultServer is the server address used if none is given or saved. It is
// the default address of the server.
const defaultServer = "localhost:8443"

var errNoCA = errors.New("CA certificate of the server is required: set " + envPrefix + "CA or --ca")

// config is the client configuration from the environment. It overrides the
// flags, and the flags override the saved state.
type config struct {
	// Session is the key printed by unlock or login.
	Session string `env:"SESSION"`
	// Server is the server address.
	Server string `env:"SERVER"`
	// CA is the path to the CA certificate the server certificate is checked
	// against.
	CA string `env:"CA"`
}

// LogValue hides the session key in slog output.
func (c config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("session", "[REDACTED]"),
		slog.String("server", c.Server),
		slog.String("ca", c.CA),
	)
}

// loadConfig reads the configuration from the environment. Returns an error
// if the environment cannot be parsed.
func loadConfig() (config, error) {
	var cfg config
	if err := env.ParseWithOptions(&cfg, env.Options{Prefix: envPrefix}); err != nil {
		return config{}, fmt.Errorf("read environment: %w", err)
	}
	return cfg, nil
}

// serverFlags are the flags of the commands that connect to a new server.
type serverFlags struct {
	server string
	ca     string
}

// add adds the flags to cmd.
func (f *serverFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.server, "server", "", "server address (default: the saved one or "+defaultServer+")")
	cmd.Flags().StringVar(&f.ca, "ca", "", "CA certificate of the server (default: the saved one)")
}

// firstSet returns the first value that is not empty, or "" if all are.
func firstSet(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
