package config

import (
	"os"
	"strings"
	"testing"
)

// 穿云 1.20.4: the core's release tags are named v5.0.0-chuanyun.N from chuanyun.25 on (was
// v5.0.0-muse.N). Both workflows that build and attach release assets must run for either prefix.
func TestMuseReleaseTagPatterns(t *testing.T) {
	for _, wf := range []string{"muse-android.yml", "mihomo.yml"} {
		raw, err := os.ReadFile("../../.github/workflows/" + wf)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		if !strings.Contains(s, "tags: ['v*-muse*', 'v*-chuanyun*']") {
			t.Fatalf("%s: tag triggers must cover v*-chuanyun* and the old v*-muse*", wf)
		}
		if !strings.Contains(s, "startsWith(github.ref, 'refs/tags/v')") {
			t.Fatalf("%s: release job must run for any v* tag", wf)
		}
	}
}
