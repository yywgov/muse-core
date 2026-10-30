//go:build cgo

// Command bridge is the mihomo core as a C shared library (Windows: muse-mihomo.dll). It exports
// the same C functions as the main core's library, so the app loads either one with the same
// bindings; everything after setup goes through the gRPC control API (package grpcsvc).
//
// Build (CI, MinGW):
//
//	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
//	  go build -buildmode=c-shared -trimpath -tags with_gvisor,no_tailscale,no_zerotier,no_easytier \
//	  -ldflags "-s -w -buildid=" -o muse-mihomo.dll ./bridge
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/yywgov/muse-core/mihomo/engine"
	"github.com/yywgov/muse-core/mihomo/grpcsvc"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
)

var svc = grpcsvc.New(&engine.Mihomo{})

func main() {}

// result: "" on success, else the error text (the caller frees it with freeString)
func result(err error) *C.char {
	if err == nil {
		return C.CString("")
	}
	return C.CString(err.Error())
}

//export setup
func setup(baseDir *C.char, workingDir *C.char, tempDir *C.char, mode C.int, listen *C.char, secret *C.char, statusPort C.longlong, debug bool) *C.char {
	return result(svc.SetupServer(&hcore.SetupRequest{
		BasePath:          C.GoString(baseDir),
		WorkingDir:        C.GoString(workingDir),
		TempDir:           C.GoString(tempDir),
		Mode:              hcore.SetupMode(mode),
		Listen:            C.GoString(listen),
		Secret:            C.GoString(secret),
		FlutterStatusPort: int64(statusPort),
		Debug:             debug,
	}))
}

//export freeString
func freeString(str *C.char) { C.free(unsafe.Pointer(str)) }

func startErr(res *hcore.CoreInfoResponse) error {
	if res.GetCoreState() == hcore.CoreStates_STARTED && res.GetMessageType() == hcore.MessageType_EMPTY {
		return nil
	}
	if res.GetMessageType() == hcore.MessageType_ALREADY_STARTED {
		return nil
	}
	return errors.New(res.GetMessageType().String() + ": " + res.GetMessage())
}

//export start
func start(configPath *C.char, disableMemoryLimit bool) *C.char {
	return result(startErr(svc.StartCore(&hcore.StartRequest{ConfigPath: C.GoString(configPath), DisableMemoryLimit: disableMemoryLimit})))
}

//export stop
func stop() *C.char {
	svc.StopCore()
	return result(nil)
}

//export restart
func restart(configPath *C.char, disableMemoryLimit bool) *C.char {
	svc.StopCore()
	return start(configPath, disableMemoryLimit)
}

//export cleanup
func cleanup() {}

//export closeGrpc
func closeGrpc(mode C.int) { svc.CloseServer(hcore.SetupMode(mode)) }

//export GetServerPublicKey
func GetServerPublicKey() *C.char { return C.CString("") }

//export AddGrpcClientPublicKey
func AddGrpcClientPublicKey(clientPublicKey *C.char) *C.char { return result(grpcsvc.ErrSecureMode) }
