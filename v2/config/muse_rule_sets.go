package config

// 穿云 1.2.4: the app ships the common rule-sets (国内 geosite/geoip, 去广告/恶意网站) and copies
// them to <base path>/rule-sets/<name>.srs. A remote rule-set with no cached copy starts from that
// file (sing-box initial_path) and is updated in the background, so connecting never waits for a
// rule-set download. A missing file is harmless: sing-box logs it and downloads as before.

import (
	"path"
	"strings"
)

func museRuleSetInitialPath(url string) string {
	name := path.Base(strings.SplitN(strings.SplitN(url, "?", 2)[0], "#", 2)[0])
	if !strings.HasSuffix(name, ".srs") || strings.Contains(name, "{") {
		return ""
	}
	return "rule-sets/" + name
}
