module github.com/canarysting/canarysting

go 1.22

// Dependencies are added as implementation proceeds. Expected early additions:
//   github.com/cilium/ebpf      // bpf/loader
//   google.golang.org/grpc      // api/proto boundary, if used
//   google.golang.org/protobuf

require (
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.2
)

require (
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)
