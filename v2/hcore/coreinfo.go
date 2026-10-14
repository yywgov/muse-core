package hcore

import (
	"fmt"
	"time"

	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"google.golang.org/grpc"
)

func SetCoreStatus(state CoreStates, msgType MessageType, message string) *CoreInfoResponse {
	msg := fmt.Sprintf("%s: %s %s", state.String(), msgType.String(), message)
	if msgType == MessageType_EMPTY {
		msg = fmt.Sprintf("%s: %s", state.String(), message)
	}
	Log(LogLevel_INFO, LogType_CORE, msg)
	static.CoreState = state
	info := CoreInfoResponse{
		CoreState:   state,
		MessageType: msgType,
		Message:     message,
	}
	static.coreInfoObserver.Publish(&info)

	return &info
}

// coreInfoResyncInterval: 穿云 1.2.1 — how often a status listener re-checks that the last state
// it sent is still the core's state. The broadcaster drops events for a slow subscriber, so a
// burst (STOPPING → STOPPED, STARTING → STARTED) could leave the app showing a stale state.
var coreInfoResyncInterval = 2 * time.Second

func (s *CoreService) CoreInfoListener(req *hcommon.Empty, stream grpc.ServerStreamingServer[CoreInfoResponse]) error {
	// 穿云 1.2.1: a larger buffer (was 1) plus a periodic resync of the latest state, so a
	// dropped event can never leave the listener on a stale state.
	coreSub := static.coreInfoObserver.Subscribe(16)
	defer static.coreInfoObserver.Unsubscribe(coreSub)
	last := static.CoreState
	if err := stream.Send(&CoreInfoResponse{
		CoreState:   last,
		MessageType: MessageType_EMPTY,
		Message:     "",
	}); err != nil {
		return err
	}
	ticker := time.NewTicker(coreInfoResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case info, ok := <-coreSub:
			if !ok || info == nil {
				// broadcaster closed: end the stream, the client re-subscribes
				return nil
			}
			if err := stream.Send(info); err != nil {
				return err
			}
			last = info.CoreState
		case <-ticker.C:
			if cur := static.CoreState; cur != last {
				if err := stream.Send(&CoreInfoResponse{
					CoreState:   cur,
					MessageType: MessageType_EMPTY,
					Message:     "",
				}); err != nil {
					return err
				}
				last = cur
			}
		}
	}
}
