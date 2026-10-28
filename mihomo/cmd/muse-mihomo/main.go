// Command muse-mihomo runs the mihomo core with its gRPC control server as a plain program
// (no cgo). Used for local runs and for measuring the size of a build on any target:
//
//	CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath \
//	  -tags with_gvisor,no_tailscale,no_zerotier,no_easytier -ldflags "-s -w -buildid=" ./cmd/muse-mihomo
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/yywgov/muse-core/mihomo/engine"
	"github.com/yywgov/muse-core/mihomo/grpcsvc"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:17078", "gRPC control address (loopback)")
	secret := flag.String("secret", "", "x-muse-token every call must carry (empty: none)")
	dir := flag.String("dir", ".", "working directory")
	flag.Parse()
	m := &engine.Mihomo{}
	svc := grpcsvc.New(m)
	if err := svc.SetupServer(&hcore.SetupRequest{WorkingDir: *dir, Listen: *listen, Secret: *secret, Mode: hcore.SetupMode_GRPC_NORMAL_INSECURE}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("mihomo %s, control API on %s\n", m.Version(), svc.Addr(hcore.SetupMode_GRPC_NORMAL_INSECURE))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	svc.StopCore()
}
