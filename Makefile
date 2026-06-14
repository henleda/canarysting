# CanarySting — developer Makefile.
# See docs/ROADMAP.md for the build plan and CLAUDE.md for the rules.
#
# Pure-Go targets (build/vet/test/fmt/tidy/run-engine) work everywhere,
# including this repo's macOS dev machines. The eBPF target (bpf) compiles the
# kernel C and only does real work on Linux with clang; see docs/STING.md and
# docs/TECHNICAL_ARCHITECTURE.md.

GO        ?= go
CLANG     ?= clang
BIN_DIR   := bin
GOBIN     := $(abspath $(BIN_DIR))

# eBPF sources -> objects. *.bpf.o is gitignored. Covers the enforcement path
# (bpf/enforce) and the M7 OBSERVE-ONLY baseline path (bpf/observe); the observe
# source lands in the on-box phase, the glob picks it up automatically.
BPF_SRC   := $(wildcard bpf/enforce/*.bpf.c bpf/observe/*.bpf.c)
BPF_OBJ   := $(BPF_SRC:.bpf.c=.bpf.o)
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Wno-unused-function

# Protobuf (api/proto). Codegen lands under api/gen per the go_package option.
PROTO_SRC := $(wildcard api/proto/*.proto)

UNAME_S := $(shell uname -s)

.DEFAULT_GOAL := help

## help: list available targets
.PHONY: help
help:
	@echo "CanarySting make targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'

## build: compile all Go packages (compile check, no binaries emitted)
.PHONY: build
build:
	$(GO) build ./...

## bin: build the binaries (engine, canaryctl) into ./bin
.PHONY: bin
bin:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/ ./cmd/...

## vet: run go vet across all packages
.PHONY: vet
vet:
	$(GO) vet ./...

## test: run the full Go test suite (race detector on)
.PHONY: test
test:
	$(GO) test -race ./...

# Packages whose behavioral tests are root-gated: they t.Skip() unless euid==0
# because they load/attach real eBPF programs to a cgroup-v2 hierarchy and key on
# the true kernel socket cookie. The committed *_bpfel.o objects are embedded, so
# these run WITHOUT clang/vmlinux.h — they need only a BPF-capable Linux kernel
# (cgroup-v2 unified) and CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON (i.e. root, or a
# privileged container). See docs/TECHNICAL_ARCHITECTURE.md "Privileged eBPF CI".
EBPF_PKGS := ./bpf/enforce/... ./bpf/observe/... ./bpf/sockops/...

## test-ebpf: run the root-gated kernel-datapath tests (Linux + root only)
# These are the jail-precision / fail-open / rate-limit / close-delete behavioral
# proofs that t.Skip() off-root. Run as root, e.g.  sudo -E make test-ebpf
# (race detector OFF: the kernel datapath is the unit under test, not Go races,
# and -race inflates loopback timing the rate-limit assertions depend on).
.PHONY: test-ebpf
test-ebpf:
ifneq ($(UNAME_S),Linux)
	@echo "test-ebpf: kernel-datapath tests run on Linux only (this is $(UNAME_S))."
	@echo "test-ebpf: use the privileged CI job or a Linux box; see docs/TECHNICAL_ARCHITECTURE.md."
	@exit 1
else
	@if [ "$$(id -u)" != "0" ]; then \
		echo "test-ebpf: must run as root (CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON + cgroup-v2 attach)."; \
		echo "test-ebpf: re-run as  sudo -E make test-ebpf"; exit 1; \
	fi
	$(GO) test -v -count=1 $(EBPF_PKGS)
endif

## fmt: format all Go source with gofmt
.PHONY: fmt
fmt:
	gofmt -s -w .

## fmt-check: fail if any Go source is not gofmt-clean (used in CI)
.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -s -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

## tidy: sync go.mod/go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## selfcheck: run the end-to-end self-check gates (no kernel/proxy needed)
.PHONY: selfcheck
selfcheck:
	$(GO) run ./cmd/sting-selfcheck
	$(GO) run ./cmd/envoy-selfcheck

## check: the full local gate (fmt-check + vet + build + test + selfcheck)
.PHONY: check
check: fmt-check vet build test selfcheck

## proto: regenerate Go from api/proto (requires protoc + protoc-gen-go)
.PHONY: proto
proto:
	@command -v protoc >/dev/null 2>&1 || { \
		echo "protoc not found — install protobuf compiler + protoc-gen-go to regenerate."; \
		echo "  (codegen is committed; you only need this when changing api/proto/*.proto)"; exit 1; }
	@mkdir -p api/gen
	protoc --go_out=. --go_opt=module=github.com/canarysting/canarysting \
		--go-grpc_out=. --go-grpc_opt=module=github.com/canarysting/canarysting \
		$(PROTO_SRC)

## bpf: compile the eBPF kernel programs with clang (real work on Linux only)
.PHONY: bpf
bpf:
ifneq ($(UNAME_S),Linux)
	@echo "bpf: skipping native eBPF object build on $(UNAME_S) — clang/bpf codegen is exercised on Linux/CI."
	@echo "bpf: (the engine, sting userspace, and tests are platform-independent; develop those here.)"
else
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "bpf: clang not found — install clang/llvm + libbpf headers."; exit 1; }
	@if [ -z "$(strip $(BPF_SRC))" ]; then echo "bpf: no bpf/enforce/*.bpf.c sources found."; exit 0; fi
	@$(MAKE) $(BPF_OBJ)
	@echo "bpf: built $(BPF_OBJ)"
endif

%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

## run-engine: run the decision engine service locally
.PHONY: run-engine
run-engine:
	$(GO) run ./cmd/engine

## attack-scripted: run the M9 zero-API scripted attacker against a local target.
## Override TARGET=... ; defaults to the staged-range demo target. Costs $0.
.PHONY: attack-scripted
attack-scripted: bin
	$(GOBIN)/llm-attacker -scripted -src-ip "" -target $(or $(TARGET),http://127.0.0.1:8080)

## demo: drive the M9 adversary against the live M7 window (run on the client box).
## Pass flags through ARGS, e.g.  make demo ARGS="--scripted"  or  make demo ARGS="--budget 0.50 --max-turns 5"
.PHONY: demo
demo:
	@deploy/m7-window/run-attack.sh $(ARGS)

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -f $(BPF_OBJ)
