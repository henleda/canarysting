module github.com/canarysting/canarysting

go 1.24

// Dependencies are added as implementation proceeds. Expected early additions:
//   github.com/cilium/ebpf      // bpf/loader
//   google.golang.org/grpc      // api/proto boundary, if used
//   google.golang.org/protobuf

require (
	github.com/anthropics/anthropic-sdk-go v1.50.0
	github.com/cilium/ebpf v0.17.1
	github.com/envoyproxy/go-control-plane/envoy v1.32.3
	go.etcd.io/bbolt v1.3.11
	golang.org/x/sys v0.35.0
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.2
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/cncf/xds/go v0.0.0-20240905190251-b4127c9b8d78 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.1.1-SNAPSHOT.5 // indirect
	github.com/invopop/jsonschema v0.14.0 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/standard-webhooks/standard-webhooks/libraries v0.0.1 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)
