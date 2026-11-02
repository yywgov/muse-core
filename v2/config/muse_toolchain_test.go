package config

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// 穿云 core muse.20: the Go toolchain must carry the crypto/x509 distrust of the compromised
// eMudhra intermediate CAs (CVE-2026-111943, fixed in go1.26.10 / go1.27.3). Older toolchains
// accept certificates forged with those keys for TLS outbounds and DoH.
func museGoPatched(v string) bool {
	v = strings.TrimPrefix(v, "go")
	if i := strings.IndexAny(v, " -+"); i >= 0 {
		v = v[:i]
	}
	p := strings.Split(v, ".")
	if len(p) < 2 {
		return false
	}
	n := make([]int, 3)
	for i := 0; i < len(p) && i < 3; i++ {
		x, err := strconv.Atoi(p[i])
		if err != nil {
			return false
		}
		n[i] = x
	}
	switch {
	case n[0] != 1:
		return n[0] > 1
	case n[1] >= 28:
		return true
	case n[1] == 27:
		return n[2] >= 3
	case n[1] == 26:
		return n[2] >= 10
	default:
		return false
	}
}

func TestMuseToolchainPatchedRule(t *testing.T) {
	for v, want := range map[string]bool{
		"go1.26.3": false, "go1.26.9": false, "go1.26.10": true, "go1.26.11": true,
		"go1.27.2": false, "go1.27.3": true, "go1.28": true, "go1.25.13": false,
		"go1.24.10": false, "devel go1.27": false, "go1.27rc1": false,
	} {
		if got := museGoPatched(v); got != want {
			t.Errorf("museGoPatched(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestMuseToolchainPatched(t *testing.T) {
	if !museGoPatched(runtime.Version()) {
		t.Fatalf("built with %s: needs go1.26.10+ (crypto/x509 eMudhra distrust, CVE-2026-111943)", runtime.Version())
	}
}
