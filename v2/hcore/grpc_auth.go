package hcore

// Muse VPN: token auth for the local gRPC control servers.
//
// On Android the INSECURE (h2c, loopback) modes are reachable by every app on
// the device. When the platform passes a non-empty SetupRequest.Secret, every
// unary and streaming call must carry metadata "x-muse-token: <secret>",
// otherwise it is rejected with Unauthenticated. An empty secret keeps the
// upstream behaviour (no auth) so desktop builds are unaffected.

import (
	"context"
	"crypto/subtle"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const GrpcTokenMetadataKey = "x-muse-token"

func checkGrpcToken(ctx context.Context, secret string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing token")
	}
	for _, v := range md.Get(GrpcTokenMetadataKey) {
		if subtle.ConstantTimeCompare([]byte(v), []byte(secret)) == 1 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "invalid token")
}

// grpcTokenServerOptions returns server options enforcing the token, or nil when secret is empty.
func grpcTokenServerOptions(secret string) []grpc.ServerOption {
	if secret == "" {
		return nil
	}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			if err := checkGrpcToken(ctx, secret); err != nil {
				return nil, err
			}
			return handler(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if err := checkGrpcToken(ss.Context(), secret); err != nil {
				return err
			}
			return handler(srv, ss)
		}),
	}
}
