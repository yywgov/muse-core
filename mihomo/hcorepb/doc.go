// Package hcorepb holds copies of the generated gRPC/protobuf code of the main core's control
// API (v2/hcore, v2/hcommon, v2/hello). The mihomo core is a separate Go module and binary, so it
// cannot import the main core's packages (they pull in the whole sing-box tree); the copies keep
// the wire format identical (same proto package "hcore", same service and messages), so the app
// talks to either core with the same client. sync_test.go fails when a copy drifts.
package hcorepb
