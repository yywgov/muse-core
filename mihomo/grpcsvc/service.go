// Package grpcsvc serves the app's core control API (proto package "hcore", the same service the
// main core serves) on top of a mihomo engine. Block M1 implements Setup, Start, Stop, the
// status stream (CoreInfoListener), GetSystemInfo / GetSystemInfoStream, LogListener, settings
// (the settings call) and Close; block M2 adds the node groups (OutboundsInfo, MainOutboundsInfo),
// SelectOutbound, UrlTest / UrlTestActive, HotReload and Restart (groups.go). Other calls answer
// Unimplemented until their block.
package grpcsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"github.com/yywgov/muse-core/mihomo/options"
	"github.com/yywgov/muse-core/mihomo/profile"
	"github.com/yywgov/muse-core/mihomo/sysproxy"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// LogEvent is one line of the engine's log.
type LogEvent struct {
	Level   string // debug, info, warning, error
	Payload string
}

// Engine is what the service needs from mihomo (package engine; a fake in tests).
type Engine interface {
	SetHomeDir(dir string)
	Parse(buf []byte) (any, error)
	Apply(parsed any)
	Stop()
	Traffic() (up, down, upTotal, downTotal int64, conns int32)
	Current(group string) string
	SubscribeLogs() (<-chan LogEvent, func())
	Version() string

	// block M2: groups, selection, delay tests, hot reload
	Nodes() map[string]NodeInfo
	Select(group, name string) error
	TestDelay(ctx context.Context, name, url string, timeout time.Duration) (uint16, error)
	Reload(parsed any)
}

// Service implements hcore.CoreServer.
type Service struct {
	hcore.UnimplementedCoreServer

	eng Engine

	mu       sync.Mutex // Start / Stop / settings
	state    atomic.Int32
	settings options.Settings
	rawSet   string
	workDir  string
	profile  *profile.Profile
	name     string

	stateHub *hub[*hcore.CoreInfoResponse]
	logHub   *hub[*hcore.LogMessage]
	logStop  func()

	running    options.Settings // settings the running config was built with
	groupOrder []string
	nodesHub   *hub[bool] // true: the node list changed; false: the core stopped
	testMu     sync.Mutex
	testing    map[string]bool

	// GroupsDebounce batches node-list changes (delay results arrive one by one), like the main core.
	GroupsDebounce time.Duration

	srvMu   sync.Mutex
	servers map[hcore.SetupMode]*grpc.Server
	addrs   map[hcore.SetupMode]string

	// SystemInfoInterval is the sample period of GetSystemInfoStream (1 s like the main core).
	SystemInfoInterval time.Duration
	// StateResync is how often a status listener re-checks the last state it sent.
	StateResync time.Duration

	// SysProxy points the system proxy at the mixed port in 系统代理 mode (Windows).
	SysProxy  sysproxy.Setter
	proxyOn   bool
	proxyPort uint16

	// tunFD: Android VPN service's TUN (SetTunFD); 0 = the core makes its own TUN
	tunFD atomic.Int32
}

// TunAdapterName names the Windows TUN adapter (and, in package engine, its description).
const TunAdapterName = "Chuanyun"

// SetTunFD hands the core the TUN the Android VPN service built (0: none).
func (s *Service) SetTunFD(fd int) { s.tunFD.Store(int32(fd)) }

// syncSystemProxy sets / blanks the system proxy for the current state (call with s.mu held).
func (s *Service) syncSystemProxy(running bool) {
	if s.SysProxy == nil {
		return
	}
	want := running && s.settings.SetSystemProxy && !s.settings.EnableTun
	if want {
		if s.proxyOn && s.proxyPort == s.settings.MixedPort {
			return
		}
		if err := s.SysProxy.Set(s.settings.MixedPort); err != nil {
			s.log(hcore.LogLevel_WARNING, "system proxy: "+err.Error())
			return
		}
		s.proxyOn, s.proxyPort = true, s.settings.MixedPort
		return
	}
	if !s.proxyOn {
		return
	}
	if err := s.SysProxy.Clear(); err != nil {
		s.log(hcore.LogLevel_WARNING, "system proxy: "+err.Error())
	}
	s.proxyOn = false
}

// New returns a stopped service.
func New(eng Engine) *Service {
	s := &Service{
		eng:                eng,
		settings:           options.Defaults(),
		stateHub:           newHub[*hcore.CoreInfoResponse](),
		logHub:             newHub[*hcore.LogMessage](),
		SystemInfoInterval: time.Second,
		StateResync:        2 * time.Second,
		nodesHub:           newHub[bool](),
		testing:            map[string]bool{},
		GroupsDebounce:     time.Second,
		SysProxy:           sysproxy.Default,
	}
	return s
}

// State is the current core state.
func (s *Service) State() hcore.CoreStates { return hcore.CoreStates(s.state.Load()) }

func (s *Service) setState(st hcore.CoreStates, mt hcore.MessageType, msg string) *hcore.CoreInfoResponse {
	s.state.Store(int32(st))
	info := &hcore.CoreInfoResponse{CoreState: st, MessageType: mt, Message: msg}
	s.stateHub.publish(info)
	level := hcore.LogLevel_INFO
	if mt != hcore.MessageType_EMPTY {
		level = hcore.LogLevel_WARNING
	}
	s.log(level, fmt.Sprintf("%s: %s %s", st, mt, msg))
	return info
}

func (s *Service) log(level hcore.LogLevel, msg string) {
	s.logHub.publish(&hcore.LogMessage{Level: level, Type: hcore.LogType_CORE, Message: msg, Time: timestamppb.Now()})
}

// Prepare sets the working directory (settings and the last start request live under data/)
// and starts forwarding the engine's log. Called by Setup; safe to call again.
func (s *Service) Prepare(workDir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if workDir != "" {
		s.workDir = workDir
		_ = os.MkdirAll(filepath.Join(workDir, "data"), 0o700)
		s.eng.SetHomeDir(filepath.Join(workDir, "data", "mihomo"))
		if b, err := os.ReadFile(s.settingsPath()); err == nil {
			if st, err := options.ParseSettings(string(b)); err == nil {
				s.settings, s.rawSet = st, string(b)
			}
		}
	}
	if s.logStop == nil {
		ch, stop := s.eng.SubscribeLogs()
		s.logStop = stop
		go func() {
			for ev := range ch {
				s.logHub.publish(&hcore.LogMessage{Level: engineLevel(ev.Level), Type: hcore.LogType_SERVICE, Message: ev.Payload, Time: timestamppb.Now()})
			}
		}()
	}
}

func engineLevel(l string) hcore.LogLevel {
	switch l {
	case "debug":
		return hcore.LogLevel_DEBUG
	case "info":
		return hcore.LogLevel_INFO
	case "warning":
		return hcore.LogLevel_WARNING
	case "error":
		return hcore.LogLevel_ERROR
	}
	return hcore.LogLevel_INFO
}

func (s *Service) settingsPath() string {
	return filepath.Join(s.workDir, "data", "mihomo-settings.json")
}
func (s *Service) lastStartPath() string {
	return filepath.Join(s.workDir, "data", "mihomo-last-start.json")
}

// ChangeHiddifySettings (proto name, kept for the wire) stores the app's settings (applied at the next Start).
func (s *Service) ChangeHiddifySettings(ctx context.Context, in *hcore.ChangeHiddifySettingsRequest) (*hcore.CoreInfoResponse, error) {
	st, err := options.ParseSettings(in.GetHiddifySettingsJson())
	if err != nil {
		return &hcore.CoreInfoResponse{CoreState: s.State(), MessageType: hcore.MessageType_ERROR_PARSING_CONFIG, Message: err.Error()}, err
	}
	s.mu.Lock()
	s.settings, s.rawSet = st, in.GetHiddifySettingsJson()
	if s.workDir != "" {
		_ = os.WriteFile(s.settingsPath(), []byte(s.rawSet), 0o600)
	}
	s.mu.Unlock()
	return &hcore.CoreInfoResponse{CoreState: s.State()}, nil
}

type lastStart struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Name    string `json:"name"`
}

func (s *Service) Start(ctx context.Context, in *hcore.StartRequest) (*hcore.CoreInfoResponse, error) {
	return s.StartCore(in), nil
}

func (s *Service) StartService(ctx context.Context, in *hcore.StartRequest) (*hcore.CoreInfoResponse, error) {
	return s.StartCore(in), nil
}

// StartCore builds the config from the request's profile and the stored settings and runs it.
func (s *Service) StartCore(in *hcore.StartRequest) *hcore.CoreInfoResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked(in)
}

// loadProfile resolves the request (or the last one) to a parsed profile.
func (s *Service) loadProfile(in *hcore.StartRequest) (*hcore.StartRequest, *profile.Profile, hcore.MessageType, error) {
	if in == nil {
		in = &hcore.StartRequest{}
	}
	if in.ConfigPath == "" && in.ConfigContent == "" && s.workDir != "" {
		if b, err := os.ReadFile(s.lastStartPath()); err == nil {
			var ls lastStart
			if json.Unmarshal(b, &ls) == nil {
				in = &hcore.StartRequest{ConfigPath: ls.Path, ConfigContent: ls.Content, ConfigName: ls.Name}
			}
		}
	}
	content := []byte(in.ConfigContent)
	if len(content) == 0 {
		if in.ConfigPath == "" {
			return in, nil, hcore.MessageType_EMPTY_CONFIGURATION, errors.New("no profile")
		}
		b, err := os.ReadFile(in.ConfigPath)
		if err != nil {
			return in, nil, hcore.MessageType_ERROR_READING_CONFIG, err
		}
		content = b
	}
	p, err := profile.Parse(content)
	if err != nil {
		return in, nil, hcore.MessageType_ERROR_PARSING_CONFIG, err
	}
	return in, p, hcore.MessageType_EMPTY, nil
}

func (s *Service) startLocked(in *hcore.StartRequest) *hcore.CoreInfoResponse {
	if st := s.State(); st != hcore.CoreStates_STOPPED {
		return &hcore.CoreInfoResponse{CoreState: st, MessageType: hcore.MessageType_ALREADY_STARTED, Message: "instance already started"}
	}
	s.setState(hcore.CoreStates_STARTING, hcore.MessageType_EMPTY, "")
	in, p, mt, err := s.loadProfile(in)
	if err != nil {
		return s.setState(hcore.CoreStates_STOPPED, mt, err.Error())
	}
	parsed, err := s.buildAndParse(p)
	if err != nil {
		return s.setState(hcore.CoreStates_STOPPED, hcore.MessageType_ERROR_BUILDING_CONFIG, err.Error())
	}
	s.logUnsupported(p)
	s.eng.Apply(parsed)
	s.adopt(in, p)
	s.syncSystemProxy(true)
	return s.setState(hcore.CoreStates_STARTED, hcore.MessageType_EMPTY, "")
}

func (s *Service) logUnsupported(p *profile.Profile) {
	for _, u := range p.Unsupported {
		s.log(hcore.LogLevel_WARNING, fmt.Sprintf("node unavailable on this core: %q (%s, %s) %s", u.Name, u.Type, u.Reason, u.Detail))
	}
}

// adopt records the running profile and request (and saves the request for a start without one).
func (s *Service) adopt(in *hcore.StartRequest, p *profile.Profile) {
	s.profile, s.name, s.running = p, in.ConfigName, s.settings
	order := []string{options.GroupSelect, options.GroupAuto}
	seen := map[string]bool{options.GroupSelect: true, options.GroupAuto: true}
	for _, g := range p.Groups {
		if n, ok := g["name"].(string); ok && !seen[n] {
			seen[n] = true
			order = append(order, n)
		}
	}
	s.groupOrder = order
	if s.workDir != "" && (in.ConfigPath != "" || in.ConfigContent != "") {
		if b, err := json.Marshal(lastStart{Path: in.ConfigPath, Content: in.ConfigContent, Name: in.ConfigName}); err == nil {
			_ = os.WriteFile(s.lastStartPath(), b, 0o600)
		}
	}
	s.nodesHub.publish(true)
}

var proxyErr = regexp.MustCompile(`^proxy (\d+): (.*)$`)

// buildAndParse renders the config and lets the engine check it. A node mihomo rejects
// ("proxy N: ...") is moved to Unsupported and the config rebuilt, so one bad node does not stop
// the whole profile.
func (s *Service) buildAndParse(p *profile.Profile) (any, error) {
	rt := options.Runtime{TunFD: int(s.tunFD.Load())}
	if runtime.GOOS == "windows" {
		rt.TunDevice = TunAdapterName
	}
	if s.settings.EnableClashAPI {
		port := s.settings.ClashAPIPort
		if port == 0 {
			port = options.Defaults().ClashAPIPort
		}
		rt.ControllerAddr = "127.0.0.1:" + strconv.Itoa(int(port))
		rt.Secret = s.settings.ClashAPISecret
	}
	for attempt := 0; attempt <= len(p.Proxies); attempt++ {
		buf, err := options.Build(p, s.settings, rt)
		if err != nil {
			return nil, err
		}
		parsed, err := s.eng.Parse(buf)
		if err == nil {
			return parsed, nil
		}
		m := proxyErr.FindStringSubmatch(err.Error())
		if m == nil {
			return nil, err
		}
		idx, _ := strconv.Atoi(m[1])
		if !p.Reject(idx, m[2]) {
			return nil, err
		}
	}
	return nil, errors.New("no usable node")
}

func (s *Service) Stop(ctx context.Context, _ *hcommon.Empty) (*hcore.CoreInfoResponse, error) {
	return s.StopCore(), nil
}

// StopCore stops the engine.
func (s *Service) StopCore() *hcore.CoreInfoResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State() == hcore.CoreStates_STOPPED {
		return s.setState(hcore.CoreStates_STOPPED, hcore.MessageType_ALREADY_STOPPED, "")
	}
	s.setState(hcore.CoreStates_STOPPING, hcore.MessageType_EMPTY, "")
	s.syncSystemProxy(false)
	s.eng.Stop()
	s.profile = nil
	s.nodesHub.publish(false)
	return s.setState(hcore.CoreStates_STOPPED, hcore.MessageType_EMPTY, "")
}

// Unsupported lists the nodes of the running profile this core cannot run.
func (s *Service) Unsupported() []profile.Unsupported {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profile == nil {
		return nil
	}
	return append([]profile.Unsupported(nil), s.profile.Unsupported...)
}

func (s *Service) CoreInfoListener(_ *hcommon.Empty, stream grpc.ServerStreamingServer[hcore.CoreInfoResponse]) error {
	sub, cancel := s.stateHub.subscribe(16)
	defer cancel()
	last := s.State()
	if err := stream.Send(&hcore.CoreInfoResponse{CoreState: last}); err != nil {
		return err
	}
	t := time.NewTicker(s.StateResync)
	defer t.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case info, ok := <-sub:
			if !ok {
				return nil
			}
			if err := stream.Send(info); err != nil {
				return err
			}
			last = info.CoreState
		case <-t.C:
			if cur := s.State(); cur != last {
				if err := stream.Send(&hcore.CoreInfoResponse{CoreState: cur}); err != nil {
					return err
				}
				last = cur
			}
		}
	}
}

func (s *Service) readInfo(prev *hcore.SystemInfo) *hcore.SystemInfo {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	info := &hcore.SystemInfo{
		Memory:     int64(ms.HeapInuse + ms.StackInuse),
		Goroutines: int32(runtime.NumGoroutine()),
	}
	if s.State() != hcore.CoreStates_STARTED {
		return info
	}
	up, down, upT, downT, conns := s.eng.Traffic()
	info.TrafficAvailable = true
	info.Uplink, info.Downlink = up, down
	info.UplinkTotal, info.DownlinkTotal = upT, downT
	info.ConnectionsOut = conns
	info.CurrentOutbound = s.eng.Current(options.GroupSelect)
	s.mu.Lock()
	info.CurrentProfile = s.name
	s.mu.Unlock()
	return info
}

func (s *Service) GetSystemInfo(ctx context.Context, _ *hcommon.Empty) (*hcore.SystemInfo, error) {
	return s.readInfo(nil), nil
}

// GetSystemInfoStream sends one sample per interval while the client listens (no work when nobody does).
func (s *Service) GetSystemInfoStream(_ *hcommon.Empty, stream grpc.ServerStreamingServer[hcore.SystemInfo]) error {
	t := time.NewTicker(s.SystemInfoInterval)
	defer t.Stop()
	cur := s.readInfo(nil)
	if err := stream.Send(cur); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-t.C:
			cur = s.readInfo(cur)
			if err := stream.Send(cur); err != nil {
				return err
			}
		}
	}
}

func (s *Service) LogListener(req *hcore.LogRequest, stream grpc.ServerStreamingServer[hcore.LogMessage]) error {
	sub, cancel := s.logHub.subscribe(64)
	defer cancel()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case m, ok := <-sub:
			if !ok {
				return nil
			}
			if m.Level < req.GetLevel() {
				continue
			}
			if err := stream.Send(m); err != nil {
				return err
			}
		}
	}
}
