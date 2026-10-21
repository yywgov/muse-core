package config

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hiddify/hinvalid"
)

const museCFUUID = "0c6a2c4e-3f1a-4b7e-9d2a-1234567890ab"
const museCFHost = "edt.example.workers.dev"

// museCreateAll parses content like a subscription and creates every outbound the way
// sing-box does at start; it returns the parsed options and the errors of failed outbounds.
func museCreateAll(t *testing.T, content string) (*option.Options, map[string]string) {
	t.Helper()
	ctx := testContext(t)
	opts, err := parseConfigContent(ctx, []byte(content), false, DefaultHiddifyOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return opts, museCreateOutbounds(t, ctx, opts.Outbounds)
}

func museCreateOutbounds(t *testing.T, ctx context.Context, outbounds []option.Outbound) map[string]string {
	t.Helper()
	failed := map[string]string{}
	for _, o := range outbounds {
		if o.Type == C.TypeHInvalidConfig {
			failed[o.Tag] = "parse"
		}
	}
	instance, err := box.New(box.Options{Context: ctx, Options: option.Options{Outbounds: outbounds}})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	defer instance.Close()
	for _, ob := range instance.Outbound().Outbounds() {
		if inv, ok := ob.(*hinvalid.Outbound); ok {
			failed[ob.Tag()] = inv.InvalidOptions.Err.Error()
		}
	}
	return failed
}

func museTLS(t *testing.T, opts *option.Options, tagPrefix string) (*option.OutboundTLSOptions, option.Outbound) {
	t.Helper()
	for _, o := range opts.Outbounds {
		if strings.HasPrefix(o.Tag, tagPrefix) {
			w, ok := o.Options.(option.OutboundTLSOptionsWrapper)
			if !ok {
				t.Fatalf("%s has no tls", o.Tag)
			}
			return w.TakeOutboundTLSOptions(), o
		}
	}
	t.Fatalf("no outbound %s", tagPrefix)
	return nil, option.Outbound{}
}

func museCFLink(ip, extra, name string) string {
	return "vless://" + museCFUUID + "@" + ip + ":443?security=tls&type=ws&host=" + museCFHost + "&sni=" + museCFHost +
		"&path=%2F%3Fed%3D2560&encryption=none" + extra + "#" + name
}

// edgetunnel / CF-Workers-SUB share links (templates from cmliu/edgetunnel _worker.js, 2026-10)
func TestMuseCFWorkerLinksStart(t *testing.T) {
	ech := base64.StdEncoding.EncodeToString([]byte("\x00\x45\xfe\x0d\x00\x41fake-ech-config-bytes"))
	links := []string{
		museCFLink("104.16.1.1", "&fp=chrome&alpn=&ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.alidns.com%2Fdns-query", "%F0%9F%87%BA%F0%9F%87%B8%E7%BE%8E%E5%9B%BD%7CCF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%891"),
		museCFLink("104.16.1.2", "&fp=chrome&alpn=", "plain"),
		museCFLink("104.16.1.3", "&fp=randomized&allowInsecure=1", "old-randomized"),
		museCFLink("104.16.1.4", "&fp=bogus", "fp-bogus"),
		museCFLink("104.16.1.5", "&fp=chrome&ech=https%3A%2F%2F1.1.1.1%2Fdns-query", "ech-dns-only"),
		museCFLink("104.16.1.6", "&fp=chrome&ech=cloudflare-ech.com", "ech-domain"),
		museCFLink("104.16.1.7", "&fp=chrome&ech="+strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(ech), "ech-base64"),
		museCFLink("104.16.1.8", "&fp=chrome&fragment=1%2C40-60%2C30-50%2Ctlshello", "fragment"),
		"vless://" + museCFUUID + "@104.16.1.9:443?security=tls&type=ws&host=" + museCFHost + "&sni=&fp=&path=%2F&encryption=none#empty-sni",
		"vless://" + museCFUUID + "@104.16.1.10:443?security=tls&type=ws&host=" + museCFHost + "&sni=" + museCFHost + "&path=%2F&encryption=aes-128-gcm#enc-cipher",
		"vless://" + museCFUUID + "@104.16.1.11:443?security=tls&type=grpc&mode=gun&authority=" + museCFHost + "&fp=chrome&sni=" + museCFHost + "&serviceName=%2F&encryption=none&alpn=#grpc",
		"vless://" + museCFUUID + "@104.16.1.12:443?security=tls&type=xhttp&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%7D&host=" + museCFHost + "&fp=chrome&sni=" + museCFHost + "&path=%2F&encryption=none&alpn=#xhttp",
		"vless://" + museCFUUID + "@104.16.1.13:80?security=none&type=ws&host=" + museCFHost + "&path=%2F%3Fed%3D2560&encryption=none#notls",
		"trojan://pass@104.16.1.14:443?security=tls&type=ws&host=" + museCFHost + "&sni=" + museCFHost + "&fp=random&path=%2F%3Fed%3D2560&ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.alidns.com%2Fdns-query#trojan-ech",
		"vless://" + museCFUUID + "@1.2.3.4:443?security=reality&sni=www.apple.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision&encryption=none#reality",
	}
	opts, failed := museCreateAll(t, strings.Join(links, "\n"))
	for tag, err := range failed {
		t.Errorf("outbound %s failed: %s", tag, err)
	}

	tls, _ := museTLS(t, opts, "🇺🇸美国|CF官方优选1")
	if tls.ECH == nil || !tls.ECH.Enabled || len(tls.ECH.Config) != 0 || tls.ECH.QueryServerName != "cloudflare-ech.com" {
		t.Errorf("edgetunnel ECH: %+v", tls.ECH)
	}
	if tls.UTLS == nil || tls.UTLS.Fingerprint != "chrome" || tls.ServerName != museCFHost {
		t.Errorf("edgetunnel tls: %+v", tls)
	}
	if tls, _ = museTLS(t, opts, "fp-bogus"); tls.UTLS.Fingerprint != "chrome" {
		t.Errorf("unknown fingerprint not mapped to chrome: %q", tls.UTLS.Fingerprint)
	}
	if tls, _ = museTLS(t, opts, "ech-dns-only"); tls.ECH == nil || len(tls.ECH.Config) != 0 || tls.ECH.QueryServerName != "" {
		t.Errorf("ech dns only: %+v", tls.ECH)
	}
	if tls, _ = museTLS(t, opts, "ech-domain"); tls.ECH == nil || tls.ECH.QueryServerName != "cloudflare-ech.com" {
		t.Errorf("ech domain: %+v", tls.ECH)
	}
	if tls, _ = museTLS(t, opts, "ech-base64"); tls.ECH == nil || len(tls.ECH.Config) != 1 || !strings.HasPrefix(tls.ECH.Config[0], "-----BEGIN ECH CONFIGS-----") {
		t.Errorf("ech base64: %+v", tls.ECH)
	}
	if tls, _ = museTLS(t, opts, "empty-sni"); tls.ServerName != museCFHost {
		t.Errorf("empty sni not filled from host: %q", tls.ServerName)
	}
	if tls, _ = museTLS(t, opts, "trojan-ech"); tls.ECH == nil || tls.ECH.QueryServerName != "cloudflare-ech.com" {
		t.Errorf("trojan ech: %+v", tls.ECH)
	}

	names := museECHQueryDomains(opts.Outbounds)
	if len(names) != 2 || !strings.Contains(","+strings.Join(names, ",")+",", ",cloudflare-ech.com,") || !strings.Contains(strings.Join(names, ","), museCFHost) {
		t.Errorf("ECH query domains = %v", names)
	}
}

// profiles parsed by core <= 5.0.0-muse.11 keep the broken PEM-wrapped value: building the
// config must still fix it.
func TestMuseFixesStoredBrokenECH(t *testing.T) {
	stored := `{"outbounds":[{"type":"vless","tag":"stored","server":"104.16.1.1","server_port":443,"uuid":"` + museCFUUID + `",
	"tls":{"enabled":true,"server_name":"` + museCFHost + `","utls":{"enabled":true,"fingerprint":"chrome"},
	"ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----\ncloudflare-ech.com+https://dns.alidns.com/dns-query\n-----END ECH CONFIGS-----"]}},
	"transport":{"type":"ws","path":"/","headers":{"Host":"` + museCFHost + `"},"max_early_data":2560,"early_data_header_name":"Sec-WebSocket-Protocol"},"packet_encoding":"xudp"}]}`
	ctx := testContext(t)
	input, err := ReadSingOptions(ctx, &ReadOptions{Content: stored})
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: input})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tls, _ := museTLS(t, built, "stored")
	if tls.ECH == nil || len(tls.ECH.Config) != 0 || tls.ECH.QueryServerName != "cloudflare-ech.com" {
		t.Fatalf("stored ECH not fixed: %+v", tls.ECH)
	}
	found := false
	for _, rule := range built.DNS.Rules {
		for _, d := range rule.DefaultOptions.Domain {
			if d == "cloudflare-ech.com" && rule.DefaultOptions.RouteOptions.Server == DNSMultiDirectTag {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no direct DNS rule for the ECH lookup")
	}
	if failed := museCreateOutbounds(t, ctx, input.Outbounds); len(failed) > 0 {
		t.Fatalf("stored outbound still fails: %v", failed)
	}
}

// Clash (edgetunnel serves Clash to clients whose UA says ClashMeta) and sing-box JSON forms
func TestMuseCFClashAndSingboxForms(t *testing.T) {
	clash := `proxies:
  - {name: 🇺🇸美国|CF官方优选1, server: 104.16.1.1, port: 443, type: vless, uuid: ` + museCFUUID + `, tls: true, servername: ` + museCFHost + `, network: ws, ws-opts: {path: "/?ed=2560", headers: {Host: ` + museCFHost + `}}, client-fingerprint: chrome, udp: true, ech-opts: {enable: true, query-server-name: cloudflare-ech.com}}
  - {name: clash-random, server: 104.16.1.2, port: 443, type: vless, uuid: ` + museCFUUID + `, tls: true, servername: ` + museCFHost + `, network: ws, ws-opts: {path: "/?ed=2560", headers: {Host: ` + museCFHost + `}}, client-fingerprint: random}
`
	_, failed := museCreateAll(t, clash)
	for tag, err := range failed {
		t.Errorf("clash outbound %s failed: %s", tag, err)
	}

	sb := `{"outbounds":[{"type":"vless","tag":"sb-ech","server":"104.16.1.1","server_port":443,"uuid":"` + museCFUUID + `","tls":{"enabled":true,"server_name":"` + museCFHost + `","utls":{"enabled":true,"fingerprint":"Chrome_Auto"},"ech":{"enabled":true,"query_server_name":"cloudflare-ech.com"}},"transport":{"type":"ws","path":"/?ed=2560","headers":{"Host":"` + museCFHost + `"}}},
	{"type":"vless","tag":"sb-bogus","server":"104.16.1.2","server_port":443,"uuid":"` + museCFUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"bogus"}},"transport":{"type":"ws","path":"/","headers":{"Host":"` + museCFHost + `"}}}]}`
	opts, failed := museCreateAll(t, sb)
	for tag, err := range failed {
		t.Errorf("sing-box outbound %s failed: %s", tag, err)
	}
	for _, o := range opts.Outbounds {
		if o.Tag != "sb-ech" {
			continue
		}
		ws := o.Options.(*option.VLESSOutboundOptions).Transport.WebsocketOptions
		if ws.Path != "/" || ws.MaxEarlyData != 2560 || ws.EarlyDataHeaderName != "Sec-WebSocket-Protocol" {
			t.Errorf("ws early data not converted: %+v", ws)
		}
	}
}

func TestMuseUTLSFingerprintNames(t *testing.T) {
	for in, want := range map[string]string{"": "", "chrome": "chrome", "Firefox": "firefox", "random": "random", "randomized": "randomized",
		"randomizednoalpn": "randomized", "safari_auto": "safari", "ios": "ios", "bogus": "chrome", "360": "360", "qq": "qq", "edge": "edge"} {
		if got := museUTLSFingerprint(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
