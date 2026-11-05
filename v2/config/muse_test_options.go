package config

import (
	"context"
	"regexp"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
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

// museSameAs (穿云 1.10.4): nodes whose configuration is exactly the same as an earlier node's
// (only the name differs — the same server listed twice, or in two subscriptions) map to that
// node; the core tests it once and shares the result. Groups and built-in outbounds are left out.
func museSameAs(ctx context.Context, outbounds []option.Outbound) map[string]string {
	first := map[string]string{}
	same := map[string]string{}
	for _, out := range outbounds {
		switch out.Type {
		case C.TypeSelector, C.TypeURLTest, C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeCustom, "":
			continue
		}
		if out.Tag == "" {
			continue
		}
		copied := out
		copied.Tag = ""
		key, err := copied.MarshalJSONContext(ctx)
		if err != nil || len(key) == 0 {
			continue
		}
		if p, ok := first[string(key)]; ok {
			same[out.Tag] = p
			continue
		}
		first[string(key)] = out.Tag
	}
	if len(same) == 0 {
		return nil
	}
	return same
}
