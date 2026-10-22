package config

import (
	"regexp"
	"time"
)

// museTestTimeout is the 测速 probe timeout the app asked for, kept within 2–15 s (0 = core default).
func museTestTimeout(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	d := time.Duration(ms) * time.Millisecond
	if d < 2*time.Second {
		d = 2 * time.Second
	}
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	return d
}

var museSplitHTTPRe = regexp.MustCompile(`(?i)([?&]type=)splithttp\b`)

// museSplitHTTPAlias rewrites share links that still say type=splithttp (the old name of XHTTP)
// to type=xhttp, which the link parser understands.
func museSplitHTTPAlias(content []byte) []byte {
	return museSplitHTTPRe.ReplaceAll(content, []byte("${1}xhttp"))
}
