package config

// 穿云 core 1.11.0 (APK 瘦身): the standard core is built without the embedded Tor, OpenVPN and
// OpenConnect outbounds (with_embedded_tor / with_openvpn / with_openconnect), which 穿云 never
// offers; everything else in the build tags stays as it was.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func museBuildTags(t *testing.T, file, prefix string) []string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	m := regexp.MustCompile(`(?m)^` + prefix + `=(\S+)`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("%s: no %s= line", file, prefix)
	}
	return strings.Split(string(m[1]), ",")
}

func TestMuseSlimStandardCoreTags(t *testing.T) {
	for _, f := range []string{"../../Makefile", "../../cmd.sh"} {
		tags := museBuildTags(t, f, "TAGS")
		set := map[string]bool{}
		for _, tag := range tags {
			set[tag] = true
		}
		for _, gone := range []string{"with_embedded_tor", "with_openvpn", "with_openconnect"} {
			if set[gone] {
				t.Errorf("%s still builds %s", f, gone)
			}
		}
		for _, kept := range []string{"with_gvisor", "with_quic", "with_wireguard", "with_utls", "with_clash_api", "with_awg", "with_naive_outbound"} {
			if !set[kept] {
				t.Errorf("%s lost %s", f, kept)
			}
		}
	}
}
