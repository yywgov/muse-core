package grpcsvc

// Block M3-4 (subscription compatibility mode): the Parse call. The app adds and updates a
// subscription by writing what it downloaded to a temp file and asking the core to check it and
// save it as the profile. The main core converts it to its own JSON; this core keeps the body
// exactly as it came (a Clash YAML subscription reaches mihomo with its own groups and rules) and
// only checks that it can be read. Nodes this core cannot run are kept in the saved body and
// reported (count in the response message); nothing is dropped. When the user goes back to the
// main core the app has that core convert the saved body (see the client's compat_profile.dart).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yywgov/muse-core/mihomo/hcorepb/hcommon"
	"github.com/yywgov/muse-core/mihomo/hcorepb/hcore"
	"github.com/yywgov/muse-core/mihomo/options"
	"github.com/yywgov/muse-core/mihomo/profile"
)

// ParseCore implements Parse:
//   - temp_path (or content) + config_path: check the body and save it unchanged at config_path
//     (written next to it first and renamed, so a failed write never leaves half a profile);
//   - temp_path or content alone: check it and answer the body unchanged;
//   - config_path alone: answer the full config this core would run for that profile (the app's
//     「查看配置」), built from the stored settings.
func (s *Service) ParseCore(in *hcore.ParseRequest) *hcore.ParseResponse {
	if in == nil {
		in = &hcore.ParseRequest{}
	}
	if in.TempPath == "" && in.Content == "" {
		if in.ConfigPath == "" {
			return parseFailed(errors.New("no profile"))
		}
		return s.renderConfig(in.ConfigPath)
	}
	body := []byte(in.Content)
	if in.TempPath != "" {
		b, err := os.ReadFile(in.TempPath)
		if err != nil {
			return parseFailed(err)
		}
		body = b
	}
	p, err := profile.Parse(body)
	if err != nil {
		return parseFailed(err)
	}
	if usable := len(p.Proxies) + len(p.Providers); usable == 0 && len(p.Unsupported) > 0 {
		// still saved: the main core may run these nodes; the user is told why this one cannot
		s.log(hcore.LogLevel_WARNING, fmt.Sprintf("subscription: none of its %d nodes runs on this core", len(p.Unsupported)))
	}
	if in.ConfigPath != "" {
		if err := writeFileAtomic(in.ConfigPath, body); err != nil {
			return parseFailed(err)
		}
	}
	res := &hcore.ParseResponse{ResponseCode: hcommon.ResponseCode_OK, Message: ParseSummary(p)}
	if in.ConfigPath == "" {
		res.Content = string(body)
	}
	return res
}

// Parse (gRPC).
func (s *Service) Parse(ctx context.Context, in *hcore.ParseRequest) (*hcore.ParseResponse, error) {
	return s.ParseCore(in), nil
}

// ParseSummary is the machine-readable result of a check: format, usable and unavailable nodes.
func ParseSummary(p *profile.Profile) string {
	return fmt.Sprintf("compat:%s nodes=%d unavailable=%d", p.Kind, len(p.Proxies), len(p.Unsupported))
}

func (s *Service) renderConfig(path string) *hcore.ParseResponse {
	b, err := os.ReadFile(path)
	if err != nil {
		return parseFailed(err)
	}
	p, err := profile.Parse(b)
	if err != nil {
		return parseFailed(err)
	}
	s.mu.Lock()
	st := s.settings
	s.mu.Unlock()
	rt := options.Runtime{}
	if st.EnableClashAPI {
		rt.ControllerAddr = fmt.Sprintf("127.0.0.1:%d", st.ClashAPIPort)
		rt.Secret = "******" // never shown
	}
	out, err := options.Build(p, st, rt)
	if err != nil {
		return parseFailed(err)
	}
	return &hcore.ParseResponse{ResponseCode: hcommon.ResponseCode_OK, Content: string(out), Message: ParseSummary(p)}
}

func parseFailed(err error) *hcore.ParseResponse {
	return &hcore.ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: err.Error()}
}

func writeFileAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".compat-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(body)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, path)
		if werr != nil {
			// Windows cannot rename over an existing file that is open elsewhere: replace it
			_ = os.Remove(path)
			werr = os.Rename(name, path)
		}
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}
