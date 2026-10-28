package grpcsvc

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func nodesFixture() map[string]NodeInfo {
	t := time.Unix(1700000000, 0)
	return map[string]NodeInfo{
		"select": {Name: "select", Type: "Selector", Group: true, GroupType: "selector", Now: "lowest", Members: []string{"lowest", "A", "B"}},
		"lowest": {Name: "lowest", Type: "URLTest", Group: true, GroupType: "urltest", Now: "A", Members: []string{"A", "B"}},
		"A":      {Name: "A", Type: "Trojan", Delay: 120, Tested: t},
		"B":      {Name: "B", Type: "Trojan", Delay: DelayFailed, Tested: t},
		"DIRECT": {Name: "DIRECT", Type: "Direct"},
	}
}

func startedWithNodes(t *testing.T) (*Service, *fakeEngine) {
	t.Helper()
	f := newFake()
	f.nodes = nodesFixture()
	s := New(f)
	s.GroupsDebounce = 20 * time.Millisecond
	if res := s.StartCore(&hcore.StartRequest{ConfigContent: links}); res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("start %v", res)
	}
	return s, f
}

func tags(items []*hcore.OutboundInfo) string {
	var out []string
	for _, i := range items {
		out = append(out, i.Tag)
	}
	return strings.Join(out, ",")
}

func TestGroupListFull(t *testing.T) {
	s, _ := startedWithNodes(t)
	list := s.GroupList(false)
	if len(list.Items) != 2 || list.Items[0].Tag != "select" || list.Items[1].Tag != "lowest" {
		t.Fatalf("groups %v", list.Items)
	}
	sel, low := list.Items[0], list.Items[1]
	if !sel.Selectable || sel.Type != "selector" || sel.Selected != "lowest" || low.Selectable || low.Type != "urltest" {
		t.Errorf("group fields %+v / %+v", sel, low)
	}
	if got := tags(sel.Items); got != "lowest,A,B,WG" {
		t.Fatalf("select items %s", got)
	}
	lw := sel.Items[0]
	if !lw.IsGroup || !lw.IsSelected || lw.GetGroupSelectedTag() != "A" || lw.GetGroupSelectedTagDisplay() != "A" || lw.UrlTestDelay != 120 || lw.Type != "URLTest" {
		t.Errorf("lowest item %+v", lw)
	}
	a, b := sel.Items[1], sel.Items[2]
	if a.IsGroup || a.IsSelected || a.UrlTestDelay != 120 || a.UrlTestTime.AsTime().Unix() != 1700000000 || a.Type != "Trojan" || !a.IsVisible {
		t.Errorf("A %+v", a)
	}
	if b.UrlTestDelay != DelayFailed {
		t.Errorf("B delay %d", b.UrlTestDelay)
	}
	wg := sel.Items[3]
	if wg.IsVisible || wg.Type != UnsupportedTypePrefix+"wireguard" || wg.UrlTestDelay != 0 {
		t.Errorf("unsupported item %+v", wg)
	}
	if got := tags(low.Items); got != "A,B" {
		t.Errorf("lowest items %s", got)
	}
	if !low.Items[0].IsSelected || low.Items[1].IsSelected {
		t.Error("lowest selection")
	}
}

func TestGroupListMainOnly(t *testing.T) {
	s, _ := startedWithNodes(t)
	list := s.GroupList(true)
	if len(list.Items) != 2 {
		t.Fatalf("%v", list.Items)
	}
	sel := list.Items[0]
	if len(sel.Items) != 1 || sel.Items[0].Tag != "lowest" || sel.Items[0].TagDisplay != "lowest → A" {
		t.Errorf("main select %v", sel.Items)
	}
	if low := list.Items[1]; len(low.Items) != 1 || low.Items[0].Tag != "A" || low.Items[0].TagDisplay != "A" {
		t.Errorf("main lowest %v", low.Items)
	}
	s.StopCore()
	if l := s.GroupList(false); len(l.Items) != 0 {
		t.Errorf("stopped list %v", l.Items)
	}
}

func TestSelectOutbound(t *testing.T) {
	s, f := startedWithNodes(t)
	ctx := context.Background()
	sub, cancel := s.nodesHub.subscribe(4)
	defer cancel()
	if r, err := s.SelectOutbound(ctx, &hcore.SelectOutboundRequest{GroupTag: "select", OutboundTag: "B"}); err != nil || r.Code != hcommon.ResponseCode_OK {
		t.Fatalf("%v %v", r, err)
	}
	if f.nodes["select"].Now != "B" {
		t.Error("not switched")
	}
	select {
	case v := <-sub:
		if !v {
			t.Error("expected a change event")
		}
	case <-time.After(time.Second):
		t.Fatal("no change event")
	}
	for _, c := range []*hcore.SelectOutboundRequest{{GroupTag: "lowest", OutboundTag: "B"}, {GroupTag: "nope", OutboundTag: "A"}, {GroupTag: "select", OutboundTag: "zzz"}} {
		if r, err := s.SelectOutbound(ctx, c); err == nil || r.Code != hcommon.ResponseCode_FAILED {
			t.Errorf("%v should fail", c)
		}
	}
	s.StopCore()
	if _, err := s.SelectOutbound(ctx, &hcore.SelectOutboundRequest{GroupTag: "select", OutboundTag: "A"}); err == nil {
		t.Error("stopped core must refuse")
	}
}

func waitTested(t *testing.T, f *fakeEngine, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		got := append([]string(nil), f.tested...)
		f.mu.Unlock()
		if len(got) >= n {
			sort.Strings(got)
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("tested %v, want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUrlTest(t *testing.T) {
	s, f := startedWithNodes(t)
	ctx := context.Background()
	if _, err := s.ChangeHiddifySettings(ctx, &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: `{"connection-test-url":"http://t.example/204","muse-test-workers":4}`}); err != nil {
		t.Fatal(err)
	}
	if r, err := s.UrlTest(ctx, &hcore.UrlTestRequest{Tag: "select"}); err != nil || r.Code != hcommon.ResponseCode_OK {
		t.Fatalf("%v %v", r, err)
	}
	got := waitTested(t, f, 2)
	if strings.Join(got, " ") != "A@http://t.example/204 B@http://t.example/204" {
		t.Errorf("group test %v", got)
	}
	waitFor(t, func() bool { return !s.Testing() })

	f.mu.Lock()
	f.tested = nil
	f.mu.Unlock()
	if _, err := s.UrlTest(ctx, &hcore.UrlTestRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := waitTested(t, f, 1); got[0] != "A@http://t.example/204" {
		t.Errorf("active test %v", got)
	}
	if _, err := s.UrlTest(ctx, &hcore.UrlTestRequest{Tag: "missing"}); err == nil {
		t.Error("unknown tag must fail")
	}
	// a node being tested is not queued twice
	waitFor(t, func() bool { return !s.Testing() })
	f.mu.Lock()
	f.tested = nil
	f.testGate = make(chan struct{})
	f.mu.Unlock()
	s.UrlTest(ctx, &hcore.UrlTestRequest{Tag: "A"})
	s.UrlTest(ctx, &hcore.UrlTestRequest{Tag: "A"})
	close(f.testGate)
	waitFor(t, func() bool { return !s.Testing() })
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	n := len(f.tested)
	f.mu.Unlock()
	if n != 1 {
		t.Errorf("A tested %d times", n)
	}
	s.StopCore()
	if _, err := s.UrlTest(ctx, &hcore.UrlTestRequest{Tag: "A"}); err == nil {
		t.Error("stopped core must refuse")
	}
}

func TestTestTargets(t *testing.T) {
	nodes := nodesFixture()
	nodes["outer"] = NodeInfo{Group: true, GroupType: "selector", Members: []string{"select", "DIRECT", "A"}}
	got := testTargets(nodes, "outer")
	if strings.Join(got, ",") != "A,B" {
		t.Errorf("nested %v", got)
	}
	if got := testTargets(nodes, "B"); len(got) != 1 || got[0] != "B" {
		t.Errorf("single %v", got)
	}
	if got := testTargets(nodes, "nope"); got != nil {
		t.Errorf("missing %v", got)
	}
}

func TestGroupsStream(t *testing.T) {
	s, _ := startedWithNodes(t)
	req := &hcore.SetupRequest{Listen: "127.0.0.1:0", Secret: "tok", Mode: hcore.SetupMode_GRPC_NORMAL_INSECURE}
	if err := s.SetupServer(req); err != nil {
		t.Fatal(err)
	}
	defer s.CloseServer(req.Mode)
	conn, ctx := dial(t, s.Addr(req.Mode), "tok")
	core := hcore.NewCoreClient(conn)
	st, err := core.OutboundsInfo(ctx, &hcommon.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Recv()
	if err != nil || len(first.Items) != 2 || first.Items[0].Selected != "lowest" {
		t.Fatalf("first %v %v", first, err)
	}
	// several changes inside the debounce window arrive as one update
	core.SelectOutbound(ctx, &hcore.SelectOutboundRequest{GroupTag: "select", OutboundTag: "A"})
	core.SelectOutbound(ctx, &hcore.SelectOutboundRequest{GroupTag: "select", OutboundTag: "B"})
	next, err := st.Recv()
	if err != nil || next.Items[0].Selected != "B" {
		t.Fatalf("update %v %v", next, err)
	}
	main, err := core.MainOutboundsInfo(ctx, &hcommon.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := main.Recv(); err != nil || len(m.Items[0].Items) != 1 || m.Items[0].Items[0].Tag != "B" {
		t.Fatalf("main %v %v", m, err)
	}
	// stopping ends both streams
	core.Stop(ctx, &hcommon.Empty{})
	if _, err := st.Recv(); err == nil {
		t.Error("stream should end on stop")
	}
	if _, err := main.Recv(); err == nil {
		t.Error("main stream should end on stop")
	}
	waitFor(t, func() bool { return s.nodesHub.count() == 0 })
	st2, _ := core.OutboundsInfo(ctx, &hcommon.Empty{})
	if _, err := st2.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("stopped core: %v", err)
	}
}

func TestHotReload(t *testing.T) {
	f := newFake()
	f.nodes = nodesFixture()
	s := New(f)
	// stopped: starts
	if r := s.HotReloadCore(&hcore.StartRequest{ConfigContent: links}); r.CoreState != hcore.CoreStates_STARTED || f.applied != 1 {
		t.Fatalf("start via hot reload %v", r)
	}
	s.SelectOutbound(context.Background(), &hcore.SelectOutboundRequest{GroupTag: "select", OutboundTag: "B"})
	states, cancel := s.stateHub.subscribe(8)
	defer cancel()
	r := s.HotReloadCore(&hcore.StartRequest{ConfigContent: "trojan://pw@a.example.com:443#A\ntrojan://pw@c.example.com:443#C\n"})
	if r.CoreState != hcore.CoreStates_STARTED || r.MessageType != hcore.MessageType_EMPTY || f.reloads != 1 || f.applied != 1 {
		t.Fatalf("reload %v reloads=%d applied=%d", r, f.reloads, f.applied)
	}
	if (<-states).CoreState != hcore.CoreStates_HOT_RELOADING || (<-states).CoreState != hcore.CoreStates_STARTED {
		t.Error("state sequence")
	}
	if f.nodes["select"].Now != "B" {
		t.Errorf("selection lost: %q", f.nodes["select"].Now)
	}
	if u := s.Unsupported(); len(u) != 0 {
		t.Errorf("new profile unsupported %v", u)
	}
	// a bad profile leaves the running core alone
	r = s.HotReloadCore(&hcore.StartRequest{ConfigContent: "nothing"})
	if r.CoreState != hcore.CoreStates_STARTED || r.MessageType != hcore.MessageType_HOT_RELOAD_FAILED || f.reloads != 1 {
		t.Errorf("bad profile %v", r)
	}
	// TUN changes need a restart
	s.ChangeHiddifySettings(context.Background(), &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: `{"enable-tun":true}`})
	r = s.HotReloadCore(&hcore.StartRequest{ConfigContent: links})
	if r.MessageType != hcore.MessageType_HOT_RELOAD_FAILED || !strings.Contains(r.Message, "TUN") || f.reloads != 1 || s.State() != hcore.CoreStates_STARTED {
		t.Errorf("tun change %v", r)
	}
	// restart applies it
	if r, _ := s.Restart(context.Background(), &hcore.StartRequest{ConfigContent: links}); r.CoreState != hcore.CoreStates_STARTED || f.stopped != 1 || f.applied != 2 {
		t.Errorf("restart %v", r)
	}
	if r := s.HotReloadCore(&hcore.StartRequest{ConfigContent: links}); r.MessageType != hcore.MessageType_EMPTY || f.reloads != 2 {
		t.Errorf("reload after restart %v", r)
	}
}
