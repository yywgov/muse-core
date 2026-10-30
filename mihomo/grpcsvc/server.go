package grpcsvc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hello"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenMetadataKey carries the secret the app passed to Setup, on every call (same as the main core).
const TokenMetadataKey = "x-muse-token"

func checkToken(ctx context.Context, secret string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing token")
	}
	for _, v := range md.Get(TokenMetadataKey) {
		if subtle.ConstantTimeCompare([]byte(v), []byte(secret)) == 1 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "invalid token")
}

func tokenOptions(secret string) []grpc.ServerOption {
	if secret == "" {
		return nil
	}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := checkToken(ctx, secret); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := checkToken(ss.Context(), secret); err != nil {
				return err
			}
			return h(srv, ss)
		}),
	}
}

type helloService struct{ hello.UnimplementedHelloServer }

func (helloService) SayHello(_ context.Context, in *hello.HelloRequest) (*hello.HelloResponse, error) {
	return &hello.HelloResponse{Message: "Hello, " + in.GetName()}, nil
}

// ErrSecureMode: the mutual-TLS modes are not offered by this core (the app uses the
// loopback + token modes on every platform).
var ErrSecureMode = errors.New("grpcsvc: only the insecure loopback modes are supported")

// SetupServer starts the control server for req.Mode (once per mode) and prepares the service.
func (s *Service) SetupServer(req *hcore.SetupRequest) error {
	s.Prepare(req.GetWorkingDir())
	switch req.GetMode() {
	case hcore.SetupMode_GRPC_NORMAL_INSECURE, hcore.SetupMode_GRPC_BACKGROUND_INSECURE:
	case hcore.SetupMode_OLD:
		return nil
	default:
		return ErrSecureMode
	}
	s.srvMu.Lock()
	defer s.srvMu.Unlock()
	if s.servers == nil {
		s.servers = map[hcore.SetupMode]*grpc.Server{}
		s.addrs = map[hcore.SetupMode]string{}
	}
	if s.servers[req.GetMode()] != nil {
		return nil
	}
	addr := req.GetListen()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("listen address %q is not loopback", addr)
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := grpc.NewServer(tokenOptions(req.GetSecret())...)
	hcore.RegisterCoreServer(srv, s)
	hello.RegisterHelloServer(srv, helloService{})
	s.servers[req.GetMode()] = srv
	s.addrs[req.GetMode()] = lis.Addr().String()
	go func() { _ = srv.Serve(lis) }()
	return nil
}

// Addr is the address the control server of a mode listens on ("" when not running).
func (s *Service) Addr(mode hcore.SetupMode) string {
	s.srvMu.Lock()
	defer s.srvMu.Unlock()
	return s.addrs[mode]
}

// CloseServer stops the control server of a mode.
func (s *Service) CloseServer(mode hcore.SetupMode) {
	s.srvMu.Lock()
	srv := s.servers[mode]
	delete(s.servers, mode)
	delete(s.addrs, mode)
	s.srvMu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

func (s *Service) Setup(ctx context.Context, req *hcore.SetupRequest) (*hcommon.Response, error) {
	if err := s.SetupServer(req); err != nil {
		return &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: err.Error()}, err
	}
	return &hcommon.Response{Code: hcommon.ResponseCode_OK}, nil
}

func (s *Service) Close(ctx context.Context, req *hcore.CloseRequest) (*hcommon.Empty, error) {
	if req == nil {
		return &hcommon.Empty{}, nil
	}
	// answer first, then stop the server this call came in on
	go s.CloseServer(req.GetMode())
	return &hcommon.Empty{}, nil
}
