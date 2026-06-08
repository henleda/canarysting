module github.com/canarysting/canarysting

go 1.22

// Dependencies are added as implementation proceeds. Expected early additions:
//   github.com/cilium/ebpf      // bpf/loader
//   google.golang.org/grpc      // api/proto boundary, if used
//   google.golang.org/protobuf

require (
	github.com/cilium/ebpf v0.17.1
	github.com/envoyproxy/go-control-plane/envoy v1.32.3
	golang.org/x/sys v0.26.0
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.2
)

require (
	github.com/cncf/xds/go v0.0.0-20240905190251-b4127c9b8d78 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.1.1-SNAPSHOT.5 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)
