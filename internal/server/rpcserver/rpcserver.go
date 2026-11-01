// Package rpcserver builds the gRPC server of GophKeeper from its services.
package rpcserver

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/vault"
)

// maxConcurrentStreams bounds the calls one connection runs at once, and with
// them the memory its messages take: up to maxConcurrentStreams times
// [pb.MaxMessageSize]. The client makes its calls one by one.
const maxConcurrentStreams = 16

// maxHeaderListSize bounds the metadata of a call, read before any check:
// a call needs only a few hundred bytes for the token and the gRPC headers.
const maxHeaderListSize = 16 << 10

// New returns a gRPC server that accepts only TLS 1.3 with cert, checks
// tokens and serves Auth and Vault. Messages may be as large as
// [pb.MaxMessageSize], so calls without a valid token are rejected before
// their message is read.
func New(cert tls.Certificate, authSvc *auth.Service, vaultSvc *vault.Service) *grpc.Server {
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.InTapHandle(authSvc.TapHandle),
		grpc.UnaryInterceptor(authSvc.UnaryInterceptor),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
		grpc.MaxHeaderListSize(maxHeaderListSize),
		grpc.MaxRecvMsgSize(pb.MaxMessageSize),
		grpc.MaxSendMsgSize(pb.MaxMessageSize),
	)
	pb.RegisterAuthServer(srv, authSvc)
	pb.RegisterVaultServer(srv, vaultSvc)
	return srv
}
