package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/AVZotov/gophkeeper/internal/client/cli"
)

// Build information, set at build time with -ldflags -X.
var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// The first signal cancels the command and restores the default action,
	// so a second one ends the process at once.
	context.AfterFunc(ctx, stop)
	err := cli.NewRootCmd(version, buildDate).ExecuteContext(ctx)
	stop()
	if err != nil {
		os.Exit(1)
	}
}
