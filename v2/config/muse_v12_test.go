package config

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// muse 1.2: the mixed (HTTP+SOCKS) inbound listens on loopback only.
func TestMuseMixedInboundLoopbackOnly(t *testing.T) {
	options := &option.Options{}
	h := DefaultHiddifyOptions()
	h.AllowConnectionFromLAN = false
	h.MixedPort = 12334
	setInbound(options, h)
	found := 0
	for _, in := range options.Inbounds {
		if in.Type != C.TypeMixed {
			continue
		}
		found++
		o := in.Options.(*option.HTTPMixedInboundOptions)
		if o.Listen == nil {
			t.Fatalf("mixed inbound %s has no listen address (would bind every interface)", in.Tag)
		}
		addr := netip.Addr(*o.Listen)
		if !addr.IsLoopback() {
			t.Fatalf("mixed inbound %s listens on %s, want loopback", in.Tag, addr)
		}
	}
	if found == 0 {
		t.Fatal("no mixed inbound")
	}
}

// muse 1.2: 自动最快 stays on its node unless another is clearly faster (tolerance 50 ms).
func TestMuseAutoFastestTolerance(t *testing.T) {
	h := DefaultHiddifyOptions()
	input := &option.Options{Outbounds: []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "a", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "1.1.1.1", ServerPort: 1080}}},
		{Type: C.TypeSOCKS, Tag: "b", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "1.1.1.2", ServerPort: 1080}}},
	}}
	options := &option.Options{}
	if err := setOutbounds(options, input, h, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	var auto *option.BalancerOutboundOptions
	for _, o := range options.Outbounds {
		if o.Tag == OutboundURLTestTag {
			auto = o.Options.(*option.BalancerOutboundOptions)
		}
	}
	if auto == nil {
		t.Fatal("no 自动最快 group")
	}
	if auto.Tolerance < 50 {
		t.Fatalf("tolerance = %d ms, want >= 50", auto.Tolerance)
	}
	if auto.InterruptExistConnections {
		t.Fatal("a new pick must not cut open connections")
	}
}

func hy2Outbound() option.Outbound {
	return option.Outbound{Type: C.TypeHysteria2, Tag: "hy", Options: &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{Server: "1.1.1.1", ServerPort: 443},
	}}
}

// muse 1.2: 「我的宽带」 applies to Hysteria2 only; blank keeps BBR.
func TestMuseHysteria2Bandwidth(t *testing.T) {
	h := DefaultHiddifyOptions()
	out := patchOutboundHysteria2Bandwidth(hy2Outbound(), *h)
	o := out.Options.(*option.Hysteria2OutboundOptions)
	if o.UpMbps != 0 || o.DownMbps != 0 {
		t.Fatalf("blank bandwidth changed the outbound: %d/%d", o.UpMbps, o.DownMbps)
	}
	h.Hysteria2UpMbps, h.Hysteria2DownMbps = 30, 200
	src := hy2Outbound()
	out = patchOutboundHysteria2Bandwidth(src, *h)
	o = out.Options.(*option.Hysteria2OutboundOptions)
	if o.UpMbps != 30 || o.DownMbps != 200 {
		t.Fatalf("got %d/%d, want 30/200", o.UpMbps, o.DownMbps)
	}
	if s := src.Options.(*option.Hysteria2OutboundOptions); s.UpMbps != 0 {
		t.Fatal("the parsed profile must not be modified in place")
	}
	socks := option.Outbound{Type: C.TypeSOCKS, Tag: "s", Options: &option.SOCKSOutboundOptions{}}
	if got := patchOutboundHysteria2Bandwidth(socks, *h); got.Options != socks.Options {
		t.Fatal("non-hysteria2 outbound changed")
	}
}

// muse 1.2: the cache file (rule-sets) is on even without the clash API.
func TestMuseCacheFileAlwaysOn(t *testing.T) {
	for _, clash := range []bool{false, true} {
		h := DefaultHiddifyOptions()
		h.EnableClashApi = clash
		options := &option.Options{}
		setExperimental(options, h)
		if options.Experimental == nil || options.Experimental.CacheFile == nil || !options.Experimental.CacheFile.Enabled {
			t.Fatalf("clash api %v: cache file off", clash)
		}
		if (options.Experimental.ClashAPI != nil) != clash {
			t.Fatalf("clash api %v: ClashAPI = %v", clash, options.Experimental.ClashAPI)
		}
	}
}
