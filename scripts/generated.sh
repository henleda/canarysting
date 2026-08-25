#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

readonly PROTOC_VERSION="35.0"
readonly PROTOC_GEN_GO_VERSION="v1.35.2"
readonly PROTOC_GEN_GO_GRPC_VERSION="1.5.1"
readonly CONTROLLER_GEN_VERSION="v0.18.0"

usage() {
	cat <<'EOF'
usage: scripts/generated.sh <check|write> [all|proto|operator]

  check  generate into an isolated temporary directory and compare with git
  write  regenerate the selected committed artifacts

The default component is all. Tool versions are pinned in this script; the
script never installs or updates tools implicitly.
EOF
}

fail() {
	printf 'generated: %s\n' "$*" >&2
	exit 1
}

require_executable() {
	local executable="$1"
	local install_hint="$2"
	if ! command -v "$executable" >/dev/null 2>&1; then
		fail "required executable not found: $executable; $install_hint"
	fi
}

require_version() {
	local label="$1"
	local expected="$2"
	local actual="$3"
	local install_hint="$4"
	if [[ "$actual" != "$expected" ]]; then
		fail "$label version mismatch: expected '$expected', got '$actual'; $install_hint"
	fi
}

mode="${1:-}"
component="${2:-all}"
if [[ "$mode" != "check" && "$mode" != "write" ]]; then
	usage >&2
	exit 2
fi
if [[ "$component" != "all" && "$component" != "proto" && "$component" != "operator" ]]; then
	usage >&2
	exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
cd "$repo_root"

go_bin="${GO:-go}"
protoc_bin="${PROTOC:-protoc}"
require_executable "$go_bin" "install the Go version declared in go.mod"

go_install_bin="$($go_bin env GOBIN)"
if [[ -z "$go_install_bin" ]]; then
	go_install_bin="$($go_bin env GOPATH)/bin"
fi
protoc_gen_go_bin="${PROTOC_GEN_GO:-$go_install_bin/protoc-gen-go}"
protoc_gen_go_grpc_bin="${PROTOC_GEN_GO_GRPC:-$go_install_bin/protoc-gen-go-grpc}"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/canarysting-generated.XXXXXX")"
trap 'rm -rf "$tmp_root"' EXIT

drift=0

generate_proto() {
	require_executable "$protoc_bin" "install protoc $PROTOC_VERSION or set PROTOC to that binary"
	require_executable "$protoc_gen_go_bin" \
		"install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
	require_executable "$protoc_gen_go_grpc_bin" \
		"install with: go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$PROTOC_GEN_GO_GRPC_VERSION"

	require_version "protoc" "libprotoc $PROTOC_VERSION" "$($protoc_bin --version)" \
		"use the exact version recorded in scripts/generated.sh"
	require_version "protoc-gen-go" "protoc-gen-go $PROTOC_GEN_GO_VERSION" \
		"$($protoc_gen_go_bin --version)" "use the exact version recorded in scripts/generated.sh"
	require_version "protoc-gen-go-grpc" "protoc-gen-go-grpc $PROTOC_GEN_GO_GRPC_VERSION" \
		"$($protoc_gen_go_grpc_bin --version)" "use the exact version recorded in scripts/generated.sh"

	local proto_out="$tmp_root/proto"
	mkdir -p "$proto_out"
	local proto_sources=(api/proto/*.proto)
	if [[ ! -e "${proto_sources[0]}" ]]; then
		fail "no protobuf sources found under api/proto"
	fi

	"$protoc_bin" \
		--plugin="protoc-gen-go=$protoc_gen_go_bin" \
		--plugin="protoc-gen-go-grpc=$protoc_gen_go_grpc_bin" \
		--go_out="$proto_out" \
		--go_opt=module=github.com/canarysting/canarysting \
		--go-grpc_out="$proto_out" \
		--go-grpc_opt=module=github.com/canarysting/canarysting \
		"${proto_sources[@]}"

	local generated_dir="$proto_out/api/gen"
	[[ -d "$generated_dir" ]] || fail "protobuf generators produced no api/gen directory"
	if [[ "$mode" == "write" ]]; then
		mkdir -p api/gen
		local generated_file
		for generated_file in "$generated_dir"/*.go; do
			cp "$generated_file" "api/gen/${generated_file##*/}"
		done
		printf 'generated: wrote protobuf output with protoc %s, protoc-gen-go %s, protoc-gen-go-grpc %s\n' \
			"$PROTOC_VERSION" "$PROTOC_GEN_GO_VERSION" "$PROTOC_GEN_GO_GRPC_VERSION"
	elif ! diff -ru "$generated_dir" api/gen; then
		printf 'generated: protobuf output is stale; run make generated\n' >&2
		drift=1
	else
		printf 'generated: protobuf output is current\n'
	fi
}

generate_operator() {
	local controller_version
	# Capture only controller-gen's stdout. On a clean Go module cache, `go tool`
	# writes dependency-download progress to stderr before executing the pinned
	# tool; folding that diagnostic stream into the version string makes a valid
	# first CI run look like a version mismatch.
	if ! controller_version="$($go_bin tool controller-gen --version)"; then
		fail "controller-gen is unavailable; keep the go.mod tool directive at $CONTROLLER_GEN_VERSION and ensure module dependencies are available"
	fi
	require_version "controller-gen" "Version: $CONTROLLER_GEN_VERSION" "$controller_version" \
		"keep the go.mod tool directive pinned to the version recorded in scripts/generated.sh"

	local operator_out="$tmp_root/operator"
	mkdir -p "$operator_out"
	"$go_bin" tool controller-gen \
		object:headerFile= \
		crd \
		paths=./internal/operator/api/... \
		output:dir="$operator_out"

	local deepcopy_name="zz_generated.deepcopy.go"
	local crd_name="deception.canarysting.io_deceptionpolicies.yaml"
	[[ -f "$operator_out/$deepcopy_name" ]] || fail "controller-gen did not produce $deepcopy_name"
	[[ -f "$operator_out/$crd_name" ]] || fail "controller-gen did not produce $crd_name"

	if [[ "$mode" == "write" ]]; then
		cp "$operator_out/$deepcopy_name" "internal/operator/api/v1alpha1/$deepcopy_name"
		cp "$operator_out/$crd_name" "config/crd/$crd_name"
		printf 'generated: wrote Kubernetes deepcopy and CRD output with controller-gen %s\n' \
			"$CONTROLLER_GEN_VERSION"
	else
		if ! diff -u "internal/operator/api/v1alpha1/$deepcopy_name" "$operator_out/$deepcopy_name"; then
			printf 'generated: Kubernetes deepcopy output is stale; run make generated\n' >&2
			drift=1
		fi
		if ! diff -u "config/crd/$crd_name" "$operator_out/$crd_name"; then
			printf 'generated: Kubernetes CRD output is stale; run make generated\n' >&2
			drift=1
		fi
		if [[ "$drift" -eq 0 ]]; then
			printf 'generated: Kubernetes deepcopy and CRD output is current\n'
		fi
	fi
}

case "$component" in
all)
	generate_proto
	generate_operator
	;;
proto)
	generate_proto
	;;
operator)
	generate_operator
	;;
esac

if [[ "$drift" -ne 0 ]]; then
	exit 1
fi
