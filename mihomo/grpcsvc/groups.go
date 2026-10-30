package grpcsvc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"github.com/yywgov/muse-core/mihomo/options"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DelayFailed is the delay reported for a failed test (the app reads ≥ 65535 as a timeout, 0 as untested).
const DelayFailed = 65535

// UnsupportedTypePrefix marks, in OutboundInfo.Type, a node of the profile this core cannot run;
// such items are sent with IsVisible false so the app can show them greyed out.
const UnsupportedTypePrefix = "unsupported:"

// NodeInfo is one proxy or group of the running config.
type NodeInfo struct {
	Name      string
	Type      string // display name, as the main core reports it (VLESS, Shadowsocks, Selector…)
	Group     bool
	GroupType string // selector, urltest, fallback, load-balance, relay
	Now       string
	Members   []string
	Delay     uint16 // 0 untested, DelayFailed failed
	Tested    time.Time
	Hidden    bool
}

var errNotStarted = errors.New("service not started")

func failed(err error) (*hcommon.Response, error) {
	return &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: err.Error()}, err
}

func ok() (*hcommon.Response, error) { return &hcommon.Response{Code: hcommon.ResponseCode_OK}, nil }

// leaf follows a group's selection down to a node (at most a few levels).
func leaf(nodes map[string]NodeInfo, name string) string {
	for i := 0; i < 8; i++ {
		n, ok := nodes[name]
		if !ok || !n.Group || n.Now == "" {
			return name
		}
		name = n.Now
	}
	return name
}

func outboundInfo(nodes map[string]NodeInfo, name string) *hcore.OutboundInfo {
	n := nodes[name]
	info := &hcore.OutboundInfo{Tag: name, TagDisplay: name, Type: n.Type, IsGroup: n.Group, IsVisible: true}
	delay, tested := n.Delay, n.Tested
	if n.Group {
		now := n.Now
		info.GroupSelectedTag = &now
		real := leaf(nodes, name)
		info.GroupSelectedTagDisplay = &real
		l := nodes[real]
		delay, tested = l.Delay, l.Tested
	}
	if delay > 0 {
		info.UrlTestDelay = int32(delay)
		info.UrlTestTime = timestamppb.New(tested)
	}
	return info
}

// GroupList renders the groups of the running config in config order, like the main core:
// onlyMain keeps just each group's selected item (labelled "item → node" for a nested group).
func (s *Service) GroupList(onlyMain bool) *hcore.OutboundGroupList {
	s.mu.Lock()
	order := append([]string(nil), s.groupOrder...)
	var unsupported []*hcore.OutboundInfo
	if s.profile != nil && !onlyMain {
		for _, u := range s.profile.Unsupported {
			unsupported = append(unsupported, &hcore.OutboundInfo{Tag: u.Name, TagDisplay: u.Name, Type: UnsupportedTypePrefix + u.Type, IsVisible: false})
		}
	}
	s.mu.Unlock()
	list := &hcore.OutboundGroupList{}
	if s.State() == hcore.CoreStates_STOPPED {
		return list
	}
	nodes := s.eng.Nodes()
	for _, name := range order {
		n, ok := nodes[name]
		if !ok || !n.Group || n.Hidden {
			continue
		}
		g := &hcore.OutboundGroup{Tag: name, Type: n.GroupType, Selected: n.Now, Selectable: n.GroupType == "selector"}
		for _, m := range n.Members {
			if onlyMain && m != n.Now {
				continue
			}
			info := outboundInfo(nodes, m)
			info.IsSelected = m == n.Now
			if onlyMain && info.GroupSelectedTagDisplay != nil && info.TagDisplay != *info.GroupSelectedTagDisplay {
				info.TagDisplay += " → " + *info.GroupSelectedTagDisplay
			}
			g.Items = append(g.Items, info)
		}
		if name == options.GroupSelect {
			g.Items = append(g.Items, unsupported...)
		}
		if len(g.Items) == 0 {
			continue
		}
		list.Items = append(list.Items, g)
	}
	return list
}

func (s *Service) OutboundsInfo(_ *hcommon.Empty, stream grpc.ServerStreamingServer[hcore.OutboundGroupList]) error {
	return s.groupsStream(stream, false)
}

func (s *Service) MainOutboundsInfo(_ *hcommon.Empty, stream grpc.ServerStreamingServer[hcore.OutboundGroupList]) error {
	return s.groupsStream(stream, true)
}

// groupsStream sends the list now and again after changes (batched by GroupsDebounce); it does no
// work while nothing changes and ends when the core stops (the app subscribes again on start).
func (s *Service) groupsStream(stream grpc.ServerStreamingServer[hcore.OutboundGroupList], onlyMain bool) error {
	if s.State() == hcore.CoreStates_STOPPED {
		return status.Error(codes.FailedPrecondition, errNotStarted.Error())
	}
	sub, cancel := s.nodesHub.subscribe(16)
	defer cancel()
	if err := stream.Send(s.GroupList(onlyMain)); err != nil {
		return err
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case changed, ok := <-sub:
			if !ok || !changed {
				return nil
			}
			if timer == nil {
				timer = time.NewTimer(s.GroupsDebounce)
				timerC = timer.C
			}
		case <-timerC:
			timer, timerC = nil, nil
			if err := stream.Send(s.GroupList(onlyMain)); err != nil {
				return err
			}
		}
	}
}

func (s *Service) SelectOutbound(ctx context.Context, in *hcore.SelectOutboundRequest) (*hcommon.Response, error) {
	if s.State() != hcore.CoreStates_STARTED && s.State() != hcore.CoreStates_HOT_RELOADING {
		return failed(errNotStarted)
	}
	if err := s.eng.Select(in.GetGroupTag(), in.GetOutboundTag()); err != nil {
		return failed(err)
	}
	s.nodesHub.publish(true)
	return ok()
}

// testTargets: a group means all nodes under it (nested groups included), a node means itself.
func testTargets(nodes map[string]NodeInfo, tag string) []string {
	n, found := nodes[tag]
	if !found {
		return nil
	}
	if !n.Group {
		return []string{tag}
	}
	var out []string
	seen := map[string]bool{}
	var walk func(string, int)
	walk = func(name string, depth int) {
		g := nodes[name]
		for _, m := range g.Members {
			mn, ok := nodes[m]
			if !ok || seen[m] {
				continue
			}
			seen[m] = true
			if mn.Group {
				if depth < 4 {
					walk(m, depth+1)
				}
				continue
			}
			if mn.Type == "Direct" || mn.Type == "Block" {
				continue
			}
			out = append(out, m)
		}
	}
	walk(tag, 0)
	return out
}

func (s *Service) UrlTest(ctx context.Context, in *hcore.UrlTestRequest) (*hcommon.Response, error) {
	if s.State() != hcore.CoreStates_STARTED {
		return failed(errNotStarted)
	}
	if in.GetTag() == "" {
		return s.UrlTestActive(ctx, nil)
	}
	targets := testTargets(s.eng.Nodes(), in.GetTag())
	if len(targets) == 0 {
		return failed(errors.New("outbound not found: " + in.GetTag()))
	}
	s.startTests(targets)
	return ok()
}

// UrlTestActive tests the node the main group currently uses.
func (s *Service) UrlTestActive(ctx context.Context, _ *hcommon.Empty) (*hcommon.Response, error) {
	if s.State() != hcore.CoreStates_STARTED {
		return failed(errNotStarted)
	}
	nodes := s.eng.Nodes()
	sel, found := nodes[options.GroupSelect]
	if !found || sel.Now == "" {
		return failed(errors.New("outbound not found in selector: " + options.GroupSelect))
	}
	s.startTests([]string{leaf(nodes, options.GroupSelect)})
	return ok()
}

// startTests runs delay tests in the background with the configured parallelism; a node already
// being tested is skipped. Each result marks the node list changed.
func (s *Service) startTests(targets []string) {
	s.mu.Lock()
	st := s.settings
	s.mu.Unlock()
	s.testMu.Lock()
	todo := targets[:0:0]
	for _, t := range targets {
		if !s.testing[t] {
			s.testing[t] = true
			todo = append(todo, t)
		}
	}
	s.testMu.Unlock()
	if len(todo) == 0 {
		return
	}
	workers := st.Workers()
	if workers > len(todo) {
		workers = len(todo)
	}
	url, timeout := st.URL(), st.TestTimeout()
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				_, _ = s.eng.TestDelay(context.Background(), name, url, timeout)
				s.testMu.Lock()
				delete(s.testing, name)
				s.testMu.Unlock()
				s.nodesHub.publish(true)
			}
		}()
	}
	go func() {
		for _, t := range todo {
			jobs <- t
		}
		close(jobs)
		wg.Wait()
	}()
}

// Testing reports whether any delay test is running.
func (s *Service) Testing() bool {
	s.testMu.Lock()
	defer s.testMu.Unlock()
	return len(s.testing) > 0
}

func (s *Service) HotReload(ctx context.Context, in *hcore.StartRequest) (*hcore.CoreInfoResponse, error) {
	return s.HotReloadCore(in), nil
}

// HotReloadCore applies a new profile/settings to the running core (listeners that did not change
// keep running; selections in select groups are kept), or starts the core when it is stopped. A
// changed TUN cannot be hot reloaded: HOT_RELOAD_FAILED, and the core keeps running unchanged.
func (s *Service) HotReloadCore(in *hcore.StartRequest) *hcore.CoreInfoResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.State() {
	case hcore.CoreStates_STOPPED:
		return s.startLocked(in)
	case hcore.CoreStates_STARTED:
	default:
		return &hcore.CoreInfoResponse{CoreState: s.State(), MessageType: hcore.MessageType_HOT_RELOAD_FAILED, Message: "core is busy"}
	}
	fail := func(msg string) *hcore.CoreInfoResponse {
		return s.setState(hcore.CoreStates_STARTED, hcore.MessageType_HOT_RELOAD_FAILED, msg)
	}
	s.setState(hcore.CoreStates_HOT_RELOADING, hcore.MessageType_EMPTY, "")
	if !s.settings.SameTun(s.running) {
		return fail("TUN settings changed; restart to apply")
	}
	in, p, _, err := s.loadProfile(in)
	if err != nil {
		return fail(err.Error())
	}
	parsed, err := s.buildAndParse(p)
	if err != nil {
		return fail(err.Error())
	}
	keep := map[string]string{}
	for name, n := range s.eng.Nodes() {
		if n.GroupType == "selector" && n.Now != "" {
			keep[name] = n.Now
		}
	}
	s.logUnsupported(p)
	s.eng.Reload(parsed)
	for g, sel := range keep {
		_ = s.eng.Select(g, sel) // a node that left the profile keeps the group's default
	}
	s.adopt(in, p)
	s.syncSystemProxy(true)
	return s.setState(hcore.CoreStates_STARTED, hcore.MessageType_EMPTY, "")
}

func (s *Service) Restart(ctx context.Context, in *hcore.StartRequest) (*hcore.CoreInfoResponse, error) {
	s.StopCore()
	return s.StartCore(in), nil
}
