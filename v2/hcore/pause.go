package hcore

import (
	"context"
	"time"

	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/sagernet/sing-box/common/monitoring"
	C "github.com/sagernet/sing-box/constant"
)

func (s *CoreService) Close(ctx context.Context, closeReq *CloseRequest) (*hcommon.Empty, error) {
	if closeReq == nil {
		return nil, nil
	}
	mode := closeReq.Mode
	if grpcServer[mode] == nil {
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already stoped")
		return nil, nil
	}

	CloseGrpcServer(mode)
	return &hcommon.Empty{}, nil
}

func Pause() {
	if box := static.Instance(); box != nil {
		if manager := box.PauseManager(); manager != nil {
			manager.DevicePause()
			if C.IsIos {
				if static.endPauseTimer == nil {
					static.endPauseTimer = time.AfterFunc(time.Minute, manager.DeviceWake)
				} else {
					static.endPauseTimer.Reset(time.Minute)
				}
			}
		}
	}
}

func Wake() {
	if box := static.Instance(); box != nil {
		if manager := box.PauseManager(); manager != nil {
			// if !C.IsIos {
			manager.DeviceWake()
			// }
		}
	}

}

// SetScreenOn (muse/穿云): while the screen is off node tests run every 15 minutes; when it
// comes back on every node is tested again at once (see patches/hiddify-sing-box 0002).
func SetScreenOn(on bool) {
	monitoring.SetScreenOn(on)
}
