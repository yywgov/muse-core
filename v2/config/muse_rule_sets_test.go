package config

import "testing"

func TestMuseRuleSetInitialPath(t *testing.T) {
	cases := map[string]string{
		"https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-cn.srs":    "rule-sets/geosite-cn.srs",
		"https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-malware.srs?x": "rule-sets/geoip-malware.srs",
		"https://example.com/list.json": "",
		"https://example.com/{tag}.srs": "",
	}
	for in, want := range cases {
		if got := museRuleSetInitialPath(in); got != want {
			t.Errorf("museRuleSetInitialPath(%q) = %q, want %q", in, got, want)
		}
	}
}
