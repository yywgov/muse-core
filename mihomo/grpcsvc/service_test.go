package grpcsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hello"
	"go.yaml.in/yaml/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeEngine struct {
	mu       sync.Mutex
	home     string
	parsed   [][]byte
	applied  int
	stopped  int
	rejectN  int // reject the first proxy this many times ("proxy 0: ...")
	parseErr error
	logs     chan LogEvent
	cancels  int
	nodes    map[string]NodeInfo
	tested   []string
	reloads  int
	testGate chan struct{} // when set, TestDelay waits on it
}

func newFake() *fakeEngine { return &fakeEngine{logs: make(chan LogEvent, 8)} }

func (f *fakeEngine) SetHomeDir(d string) { f.mu.Lock(); f.home = d; f.mu.Unlock() }
func (f *fakeEngine) Parse(b []byte) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.parsed = append(f.parsed, b)
	if f.parseErr != nil {
		return nil, f.parseErr
	}
	if f.rejectN > 0 {
		f.rejectN--
		return nil, errors.New("proxy 0: unsupported cipher")
	}
	return string(b), nil
}
func (f *fakeEngine) Apply(any) { f.mu.Lock(); f.applied++; f.mu.Unlock() }
func (f *fakeEngine) Stop()     { f.mu.Lock(); f.stopped++; f.mu.Unlock() }
func (f *fakeEngine) Traffic() (int64, int64, int64, int64, int32) {
	return 10, 20, 1000, 2000, 3
}
func (f *fakeEngine) Current(string) string { return "lowest→A" }
func (f *fakeEngine) SubscribeLogs() (<-chan LogEvent, func()) {
	return f.logs, func() { f.mu.Lock(); f.cancels++; f.mu.Unlock() }
}
func (f *fakeEngine) Version() string { return "test" }

func (f *fakeEngine) Nodes() map[string]NodeInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]NodeInfo{}
	for k, v := range f.nodes {
		v.Members = append([]string(nil), v.Members...)
		out[k] = v
	}
	return out
}
func (f *fakeEngine) Select(group, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.nodes[group]
	if !ok {
		return errors.New("selector not found: " + group)
	}
	if g.GroupType != "selector" {
		return errors.New("outbound is not a selector")
	}
	for _, m := range g.Members {
		if m == name {
			g.Now = name
			f.nodes[group] = g
			return nil
		}
	}
	return errors.New("proxy not exist")
}
func (f *fakeEngine) TestDelay(ctx context.Context, name, url string, timeout time.Duration) (uint16, error) {
	if f.testGate != nil {
		<-f.testGate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tested = append(f.tested, name+"@"+url)
	n := f.nodes[name]
	n.Delay, n.Tested = uint16(100+len(f.tested)), time.Unix(1700000000, 0)
	f.nodes[name] = n
	return n.Delay, nil
}
func (f *fakeEngine) Reload(any) { f.mu.Lock(); f.reloads++; f.mu.Unlock() }

func (f *fakeEngine) lastConfig(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var m map[string]any
	if err := yaml.Unmarshal(f.parsed[len(f.parsed)-1], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const links = "trojan://pw@a.example.com:443#A\ntrojan://pw@b.example.com:443#B\nwireguard://k@c.example.com:51820#WG\n"

func writeProfile(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "profile.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStartStopStates(t *testing.T) {
	f := newFake()
	s := New(f)
	dir := t.TempDir()
	s.Prepare(dir)
	if f.home != filepath.Join(dir, "data", "mihomo") {
		t.Errorf("home %q", f.home)
	}
	sub, cancel := s.stateHub.subscribe(16)
	defer cancel()

	path := writeProfile(t, dir, links)
	res := s.StartCore(&hcore.StartRequest{ConfigPath: path, ConfigName: "My sub"})
	if res.CoreState != hcore.CoreStates_STARTED || res.MessageType != hcore.MessageType_EMPTY {
		t.Fatalf("start %v", res)
	}
	if got := []hcore.CoreStates{(<-sub).CoreState, (<-sub).CoreState}; got[0] != hcore.CoreStates_STARTING || got[1] != hcore.CoreStates_STARTED {
		t.Errorf("published %v", got)
	}
	if f.applied != 1 {
		t.Errorf("applied %d", f.applied)
	}
	if u := s.Unsupported(); len(u) != 1 || u[0].Name != "WG" {
		t.Errorf("unsupported %v", u)
	}
	res = s.StartCore(&hcore.StartRequest{ConfigPath: path})
	if res.MessageType != hcore.MessageType_ALREADY_STARTED || f.applied != 1 {
		t.Errorf("second start %v", res)
	}
	info := s.readInfo(nil)
	if !info.TrafficAvailable || info.Uplink != 10 || info.DownlinkTotal != 2000 || info.ConnectionsOut != 3 ||
		info.CurrentOutbound != "lowest→A" || info.CurrentProfile != "My sub" || info.Memory <= 0 {
		t.Errorf("info %+v", info)
	}
	res = s.StopCore()
	if res.CoreState != hcore.CoreStates_STOPPED || f.stopped != 1 {
		t.Fatalf("stop %v", res)
	}
	if res = s.StopCore(); res.MessageType != hcore.MessageType_ALREADY_STOPPED || f.stopped != 1 {
		t.Errorf("second stop %v", res)
	}
	if info := s.readInfo(nil); info.TrafficAvailable || info.CurrentOutbound != "" {
		t.Errorf("stopped info %+v", info)
	}
	if s.Unsupported() != nil {
		t.Error("unsupported list must clear on stop")
	}
}

func TestStartErrors(t *testing.T) {
	f := newFake()
	s := New(f)
	dir := t.TempDir()
	s.Prepare(dir)
	cases := []struct {
		req  *hcore.StartRequest
		want hcore.MessageType
	}{
		{&hcore.StartRequest{}, hcore.MessageType_EMPTY_CONFIGURATION},
		{&hcore.StartRequest{ConfigPath: filepath.Join(dir, "missing")}, hcore.MessageType_ERROR_READING_CONFIG},
		{&hcore.StartRequest{ConfigContent: "nothing useful"}, hcore.MessageType_ERROR_PARSING_CONFIG},
		{&hcore.StartRequest{ConfigContent: `{"outbounds":[]}`}, hcore.MessageType_ERROR_PARSING_CONFIG},
	}
	for i, c := range cases {
		res := s.StartCore(c.req)
		if res.CoreState != hcore.CoreStates_STOPPED || res.MessageType != c.want {
			t.Errorf("case %d: %v", i, res)
		}
	}
	f.parseErr = errors.New("rules[0] bad")
	res := s.StartCore(&hcore.StartRequest{ConfigContent: links})
	if res.MessageType != hcore.MessageType_ERROR_BUILDING_CONFIG || !strings.Contains(res.Message, "rules[0]") || f.applied != 0 {
		t.Errorf("engine error: %v", res)
	}
}

func TestRejectedNodeIsMarkedAndRestRuns(t *testing.T) {
	f := newFake()
	f.rejectN = 1
	s := New(f)
	res := s.StartCore(&hcore.StartRequest{ConfigContent: links})
	if res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("%v", res)
	}
	if len(f.parsed) != 2 {
		t.Errorf("parsed %d times", len(f.parsed))
	}
	cfg := f.lastConfig(t)
	if px := cfg["proxies"].([]any); len(px) != 1 || px[0].(map[string]any)["name"] != "B" {
		t.Errorf("proxies %v", px)
	}
	u := s.Unsupported()
	if len(u) != 2 || u[1].Name != "A" || u[1].Detail != "unsupported cipher" {
		t.Errorf("unsupported %v", u)
	}
	// every node refused: the start fails instead of looping
	f2 := newFake()
	f2.rejectN = 100
	s2 := New(f2)
	if res := s2.StartCore(&hcore.StartRequest{ConfigContent: links}); res.CoreState != hcore.CoreStates_STOPPED {
		t.Errorf("%v", res)
	}
	if len(f2.parsed) > 3 {
		t.Errorf("parsed %d times for 2 nodes", len(f2.parsed))
	}
}

func TestSettingsPersistAndLastStart(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	s := New(f)
	s.Prepare(dir)
	if _, err := s.ChangeHiddifySettings(context.Background(), &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: `{"mixed-port":2080,"enable-clash-api":true,"clash-api-port":9090,"web-secret":"w"}`}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeHiddifySettings(context.Background(), &hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: `{bad`}); err == nil {
		t.Fatal("bad settings must fail")
	}
	path := writeProfile(t, dir, links)
	s.StartCore(&hcore.StartRequest{ConfigPath: path, ConfigName: "n"})
	cfg := f.lastConfig(t)
	if cfg["mixed-port"] != 2080 || cfg["external-controller"] != "127.0.0.1:9090" || cfg["secret"] != "w" {
		t.Errorf("cfg %v %v %v", cfg["mixed-port"], cfg["external-controller"], cfg["secret"])
	}
	s.StopCore()

	// a new process: settings and the last profile come back from disk
	f2 := newFake()
	s2 := New(f2)
	s2.Prepare(dir)
	res := s2.StartCore(&hcore.StartRequest{})
	if res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("%v", res)
	}
	cfg = f2.lastConfig(t)
	if cfg["mixed-port"] != 2080 {
		t.Errorf("settings not restored: %v", cfg["mixed-port"])
	}
	if s2.readInfo(nil).CurrentProfile != "n" {
		t.Error("name not restored")
	}
}

func dial(t *testing.T, addr, token string) (*grpc.ClientConn, context.Context) {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, TokenMetadataKey, token)
	}
	return conn, ctx
}

func TestGRPCServerTokenAndCalls(t *testing.T) {
	f := newFake()
	s := New(f)
	s.SystemInfoInterval = 20 * time.Millisecond
	s.StateResync = 20 * time.Millisecond
	dir := t.TempDir()
	req := &hcore.SetupRequest{WorkingDir: dir, Listen: "127.0.0.1:0", Secret: "tok", Mode: hcore.SetupMode_GRPC_NORMAL_INSECURE}
	if err := s.SetupServer(req); err != nil {
		t.Fatal(err)
	}
	defer s.CloseServer(req.Mode)
	if err := s.SetupServer(req); err != nil {
		t.Fatalf("second setup must be a no-op: %v", err)
	}
	addr := s.Addr(req.Mode)
	if addr == "" {
		t.Fatal("no address")
	}

	conn, _ := dial(t, addr, "")
	if _, err := hello.NewHelloClient(conn).SayHello(context.Background(), &hello.HelloRequest{Name: "x"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	bad := metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, "nope")
	if _, err := hcore.NewCoreClient(conn).GetSystemInfo(bad, &hcommon.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad token: %v", err)
	}

	conn, ctx := dial(t, addr, "tok")
	if r, err := hello.NewHelloClient(conn).SayHello(ctx, &hello.HelloRequest{Name: "x"}); err != nil || r.Message != "Hello, x" {
		t.Fatalf("hello %v %v", r, err)
	}
	core := hcore.NewCoreClient(conn)

	sctx, scancel := context.WithCancel(ctx)
	states, err := core.CoreInfoListener(sctx, &hcommon.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if first, err := states.Recv(); err != nil || first.CoreState != hcore.CoreStates_STOPPED {
		t.Fatalf("first state %v %v", first, err)
	}
	logs, err := core.LogListener(sctx, &hcore.LogRequest{Level: hcore.LogLevel_WARNING})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.logHub.count() == 1 })

	res, err := core.Start(ctx, &hcore.StartRequest{ConfigContent: links})
	if err != nil || res.CoreState != hcore.CoreStates_STARTED {
		t.Fatalf("start %v %v", res, err)
	}
	seen := map[hcore.CoreStates]bool{}
	for !seen[hcore.CoreStates_STARTED] {
		m, err := states.Recv()
		if err != nil {
			t.Fatal(err)
		}
		seen[m.CoreState] = true
	}
	// the WireGuard link is reported at WARNING; INFO state lines are filtered out
	lm, err := logs.Recv()
	if err != nil || lm.Level < hcore.LogLevel_WARNING || !strings.Contains(lm.Message, "WG") {
		t.Fatalf("log %v %v", lm, err)
	}
	f.logs <- LogEvent{Level: "error", Payload: "engine says hi"}
	for {
		lm, err = logs.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if lm.Message == "engine says hi" {
			if lm.Level != hcore.LogLevel_ERROR || lm.Type != hcore.LogType_SERVICE {
				t.Errorf("engine log %v", lm)
			}
			break
		}
	}

	info, err := core.GetSystemInfoStream(sctx, &hcommon.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		m, err := info.Recv()
		if err != nil || !m.TrafficAvailable || m.Downlink != 20 {
			t.Fatalf("info %v %v", m, err)
		}
	}
	if r, err := core.Stop(ctx, &hcommon.Empty{}); err != nil || r.CoreState != hcore.CoreStates_STOPPED {
		t.Fatalf("stop %v %v", r, err)
	}
	scancel()
	// cancelled streams leave no subscriber behind
	waitFor(t, func() bool { return s.logHub.count() == 0 && s.stateHub.count() == 0 })

	// calls of later blocks answer Unimplemented
	if _, err := core.GenerateWarpConfig(ctx, &hcore.GenerateWarpConfigRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("GenerateWarpConfig: %v", err)
	}
}

func TestSetupRejectsNonLoopbackAndSecureModes(t *testing.T) {
	s := New(newFake())
	for _, c := range []*hcore.SetupRequest{
		{Listen: "0.0.0.0:0", Mode: hcore.SetupMode_GRPC_NORMAL_INSECURE},
		{Listen: "nope", Mode: hcore.SetupMode_GRPC_NORMAL_INSECURE},
		{Listen: "127.0.0.1:0", Mode: hcore.SetupMode_GRPC_NORMAL},
	} {
		if err := s.SetupServer(c); err == nil {
			t.Errorf("%v should fail", c)
			s.CloseServer(c.Mode)
		}
	}
	if r, err := s.Setup(context.Background(), &hcore.SetupRequest{Listen: "0.0.0.0:1", Mode: hcore.SetupMode_GRPC_BACKGROUND_INSECURE}); err == nil || r.Code != hcommon.ResponseCode_FAILED {
		t.Errorf("%v %v", r, err)
	}
}

func TestCloseStopsServer(t *testing.T) {
	s := New(newFake())
	req := &hcore.SetupRequest{Listen: "127.0.0.1:0", Mode: hcore.SetupMode_GRPC_BACKGROUND_INSECURE}
	if err := s.SetupServer(req); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Close(context.Background(), &hcore.CloseRequest{Mode: req.Mode}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.Addr(req.Mode) == "" })
}

func TestPrepareSubscribesLogsOnce(t *testing.T) {
	f := newFake()
	s := New(f)
	s.Prepare("")
	s.Prepare("")
	sub, cancel := s.logHub.subscribe(4)
	defer cancel()
	f.logs <- LogEvent{Level: "debug", Payload: "one"}
	select {
	case m := <-sub:
		if m.Message != "one" || m.Level != hcore.LogLevel_DEBUG {
			t.Errorf("%v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no log")
	}
	select {
	case m := <-sub:
		t.Fatalf("log forwarded twice: %v", m)
	case <-time.After(50 * time.Millisecond):
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
