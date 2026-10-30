package hcorepb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The copies must equal the main core's generated files except for the hcommon import path.
func TestGeneratedCopiesInSync(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Skipf("main core sources not checked out: %v", err)
	}
	line, _, _ := bytes.Cut(mod, []byte("\n"))
	fromImport := string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("module")))) + "/v2/hcommon"
	const toImport = "github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	pairs := map[string]string{
		"../../v2/hcore/hcore.pb.go":              "hcore/hcore.pb.go",
		"../../v2/hcore/hcore_service.pb.go":      "hcore/hcore_service.pb.go",
		"../../v2/hcore/hcore_service_grpc.pb.go": "hcore/hcore_service_grpc.pb.go",
		"../../v2/hello/hello.pb.go":              "hello/hello.pb.go",
		"../../v2/hello/hello_service.pb.go":      "hello/hello_service.pb.go",
		"../../v2/hello/hello_service_grpc.pb.go": "hello/hello_service_grpc.pb.go",
		"../../v2/hcommon/common.pb.go":           "hcommon/common.pb.go",
	}
	for src, dst := range pairs {
		want, err := os.ReadFile(filepath.FromSlash(src))
		if err != nil {
			if os.IsNotExist(err) {
				t.Skipf("main core sources not checked out: %v", err)
			}
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.FromSlash(dst))
		if err != nil {
			t.Fatal(err)
		}
		want = bytes.ReplaceAll(want, []byte(fromImport), []byte(toImport))
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from %s; re-copy it (see doc.go)", dst, src)
		}
	}
}
