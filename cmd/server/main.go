package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/storage"
)

// shutdownTimeout bounds the graceful stop. Calls still running after it are
// cancelled.
const shutdownTimeout = 10 * time.Second

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// The first signal starts the graceful stop and restores the default
	// action, so a second one ends the process at once.
	context.AfterFunc(ctx, stop)
	err := run(ctx, log, os.Args[1:])
	stop()
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// run starts the server and serves until ctx is done, then stops it
// gracefully. Returns an error if the configuration is invalid or the
// server cannot start.
func run(ctx context.Context, log *slog.Logger, args []string) error {
	cfg, err := loadConfig(args)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	store, err := storage.Open(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	svc, err := auth.NewService(store, cfg.Secret, log)
	if err != nil {
		return fmt.Errorf("create auth service: %w", err)
	}

	lis, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := newGRPCServer(cert, svc)
	log.Info("server started", "address", lis.Addr().String())
	return serve(ctx, log, srv, lis)
}

// newGRPCServer returns a gRPC server that accepts only TLS 1.3 with cert,
// checks tokens and serves Auth.
func newGRPCServer(cert tls.Certificate, svc *auth.Service) *grpc.Server {
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	srv := grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(svc.UnaryInterceptor))
	pb.RegisterAuthServer(srv, svc)
	return srv
}

// serve serves on lis until ctx is done, then waits for calls in progress
// for up to [shutdownTimeout] and stops. Returns an error if serving fails
// before that.
func serve(ctx context.Context, log *slog.Logger, srv *grpc.Server, lis net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(lis) }()

	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down")
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(shutdownTimeout):
		log.Warn("graceful stop timed out, cancelling calls in progress")
		srv.Stop()
		<-stopped
	}
	// Serve returns ErrServerStopped if the stop came before it started.
	if err := <-errc; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("server stopped")
	return nil
}
