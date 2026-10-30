//go:build android && cgo

// Command android is the mihomo core as an Android JNI library (libmusecompat.so), loaded only
// in the app's separate VPN process (the main process keeps the main core's Go runtime; two Go
// runtimes never share a process). The VPN service builds the TUN and hands its descriptor over;
// everything else goes through the same gRPC control API as on Windows (package grpcsvc).
//
// Build (CI, NDK):
//
//	CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
//	  go build -buildmode=c-shared -trimpath -tags with_gvisor,no_tailscale,no_zerotier,no_easytier \
//	  -ldflags "-s -w -buildid=" -o libmusecompat.so ./android
//
// JNI entry points (class com.hiddify.hiddify.bg.CompatCore) are in jni.c.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"runtime/debug"
	"unsafe"

	"github.com/yywgov/muse-core/mihomo/engine"
	"github.com/yywgov/muse-core/mihomo/grpcsvc"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
)

var svc = grpcsvc.New(&engine.Mihomo{})

func main() {}

//export museCompatSetup
func museCompatSetup(base, work, temp, listen, secret *C.char, dbg C.int) *C.char {
	err := svc.SetupServer(&hcore.SetupRequest{
		BasePath:   C.GoString(base),
		WorkingDir: C.GoString(work),
		TempDir:    C.GoString(temp),
		Mode:       hcore.SetupMode_GRPC_BACKGROUND_INSECURE,
		Listen:     C.GoString(listen),
		Secret:     C.GoString(secret),
		Debug:      dbg != 0,
	})
	if err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}

//export museCompatSetTunFd
func museCompatSetTunFd(fd C.int) { svc.SetTunFD(int(fd)) }

// museCompatStop stops the engine and the control server, and gives the memory back.
//
//export museCompatStop
func museCompatStop() {
	svc.StopCore()
	svc.CloseServer(hcore.SetupMode_GRPC_BACKGROUND_INSECURE)
	svc.SetTunFD(0)
	debug.FreeOSMemory()
}

//export museCompatVersion
func museCompatVersion() *C.char { return C.CString((&engine.Mihomo{}).Version()) }

//export museCompatFree
func museCompatFree(p *C.char) { C.free(unsafe.Pointer(p)) }
