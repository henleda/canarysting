# CanarySting — developer Makefile.
# See docs/DEVELOPMENT_PLAN.md for the build plan and AGENTS.md for the rules.
#
# Pure-Go targets (build/vet/test/fmt/tidy/run-engine) work everywhere,
# including this repo's macOS dev machines. The eBPF target (bpf) compiles the
# kernel C and only does real work on Linux with clang; see docs/STING.md and
# docs/TECHNICAL_ARCHITECTURE.md.

GO        ?= go
CLANG     ?= clang
NPM       ?= npm
BIN_DIR   := bin
GOBIN     := $(abspath $(BIN_DIR))
DASHBOARD_DIR := dashboard/app
TESTGATE_GOCACHE ?= $(abspath .test-artifacts/cache/go-build)
TESTGATE ?= GOCACHE=$(TESTGATE_GOCACHE) $(GO) run ./cmd/testgate
CHECK ?=
SCENARIO ?=
COUNT ?= 1
JOBS ?=
VALIDATION_TIER ?= local
RISK ?=
GITHUB_OUTPUT_FILE ?=
DGX_PROFILE ?=
RUN_ID ?=

# eBPF sources -> objects. *.bpf.o is gitignored. Source discovery is deliberately
# narrow: enforcement, observe-only flow accounting, and the socket-cookie join.
BPF_SRC   := $(wildcard bpf/enforce/*.bpf.c bpf/observe/*.bpf.c bpf/sockops/*.bpf.c)
BPF_OBJ   := $(BPF_SRC:.bpf.c=.bpf.o)
BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Wno-unused-function

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

## frontend-check: lint, build, and run fixture-driven Playwright journeys
.PHONY: frontend-check
frontend-check:
	@command -v $(NPM) >/dev/null 2>&1 || { echo "frontend-check: npm not found — install Node.js/npm first."; exit 1; }
	@test -f $(DASHBOARD_DIR)/package-lock.json || { echo "frontend-check: missing $(DASHBOARD_DIR)/package-lock.json."; exit 1; }
	@test -d $(DASHBOARD_DIR)/node_modules || { echo "frontend-check: dependencies missing — run 'cd $(DASHBOARD_DIR) && npm ci' explicitly first."; exit 1; }
	cd $(DASHBOARD_DIR) && NEXT_TELEMETRY_DISABLED=1 $(NPM) run lint
	cd $(DASHBOARD_DIR) && NEXT_TELEMETRY_DISABLED=1 $(NPM) run build
	cd $(DASHBOARD_DIR) && NEXT_TELEMETRY_DISABLED=1 $(NPM) run test:e2e

## dgx-harness-check: validate local-only DGX harness contracts and negative cases
.PHONY: dgx-harness-check
dgx-harness-check:
	bash -n scripts/dgx/*.sh
	scripts/dgx/build_test.sh
	scripts/dgx/copy_test.sh
	scripts/dgx/run_test.sh
	scripts/dgx/cookiespike_test.sh
	scripts/dgx/enforcespike_test.sh
	scripts/dgx/dgxstackspike_test.sh
	scripts/dgx/correlationspike_test.sh
	scripts/dgx/tracespike_test.sh
	scripts/dgx/collect_test.sh
	scripts/dgx/cleanup_test.sh
	scripts/dgx/pr_test.sh

## dgx-syntax-check: validate every DGX shell program without contacting the DGX
.PHONY: dgx-syntax-check
dgx-syntax-check:
	bash -n scripts/dgx/*.sh

TESTGATE_JOBS := $(if $(strip $(JOBS)),--jobs $(JOBS),)
TESTGATE_RISK := $(if $(strip $(RISK)),--risk $(RISK),)
TESTGATE_GITHUB_OUTPUT := $(if $(strip $(GITHUB_OUTPUT_FILE)),--github-output $(GITHUB_OUTPUT_FILE),)

## check-risk: explain automatic PR risk, selected checks, and remote profiles; RISK may only increase coverage
.PHONY: check-risk
check-risk:
	$(TESTGATE) classify $(TESTGATE_RISK) $(TESTGATE_GITHUB_OUTPUT)

## preflight: collect all cheap independent structural and toolchain failures
.PHONY: preflight
preflight:
	$(TESTGATE) run --gate preflight $(TESTGATE_JOBS)

## check-fast: conservatively select checks affected by local changes (not merge qualification)
.PHONY: check-fast
check-fast:
	$(TESTGATE) run --gate check-fast $(TESTGATE_RISK) $(TESTGATE_JOBS)

## check-pr-local: Level 1 recommended pre-push check; full static/build plus affected tests and deterministic replay
.PHONY: check-pr-local
check-pr-local:
	$(TESTGATE) run --gate check-pr-local $(TESTGATE_RISK) $(TESTGATE_JOBS)

## check-pr: Level 2 authoritative risk-selected PR gate; CI adds selected remote jobs
.PHONY: check-pr
check-pr:
	$(TESTGATE) run --gate check-pr $(TESTGATE_RISK) $(TESTGATE_JOBS)

## check-local: run the complete non-privileged local suite with collect-all reporting
.PHONY: check-local
check-local:
	$(TESTGATE) run --gate check-local $(TESTGATE_JOBS)

## check-adversarial: run every bounded local adversarial scenario independently
.PHONY: check-adversarial
check-adversarial:
	$(TESTGATE) run --gate check-adversarial $(TESTGATE_JOBS)

## check-last-failed: replay the latest compatible failures, blocks, and prerequisites
.PHONY: check-last-failed
check-last-failed:
	$(TESTGATE) run --gate check-local --last-failed $(TESTGATE_JOBS)

## check-adversarial-last-failed: replay only adversarial failures from the compatible ledger
.PHONY: check-adversarial-last-failed
check-adversarial-last-failed:
	$(TESTGATE) run --gate check-adversarial --adversarial-last-failed $(TESTGATE_JOBS)

## check-one: run CHECK=<check-id> plus its prerequisites
.PHONY: check-one
check-one:
	@test -n "$(CHECK)" || { echo "check-one: CHECK=<check-id> is required"; exit 2; }
	$(TESTGATE) run --gate check-local --check "$(CHECK)" $(TESTGATE_JOBS)

## adversarial-one: run SCENARIO=<scenario-id> plus its prerequisites and cleanup
.PHONY: adversarial-one
adversarial-one:
	@test -n "$(SCENARIO)" || { echo "adversarial-one: SCENARIO=<scenario-id> is required"; exit 2; }
	$(TESTGATE) run --gate check-adversarial --check "adversarial:$(SCENARIO)" $(TESTGATE_JOBS)

## check-repeat: repeat CHECK=<check-id> COUNT=<n>; any iteration failure fails the command
.PHONY: check-repeat
check-repeat:
	@test -n "$(CHECK)" || { echo "check-repeat: CHECK=<check-id> is required"; exit 2; }
	$(TESTGATE) run --gate check-local --check "$(CHECK)" --repeat "$(COUNT)" $(TESTGATE_JOBS)

## adversarial-repeat: repeat SCENARIO=<scenario-id> COUNT=<n> with deterministic seed evidence
.PHONY: adversarial-repeat
adversarial-repeat:
	@test -n "$(SCENARIO)" || { echo "adversarial-repeat: SCENARIO=<scenario-id> is required"; exit 2; }
	$(TESTGATE) run --gate check-adversarial --check "adversarial:$(SCENARIO)" --repeat "$(COUNT)" $(TESTGATE_JOBS)

## check-merge-local: run every required non-privileged local merge check and adversarial scenario
.PHONY: check-merge-local
check-merge-local: check-integration-full

## check-integration-full: Level 3 complete local race, integration, replay, frontend, eBPF compile, and harness matrix
.PHONY: check-integration-full
check-integration-full:
	$(TESTGATE) run --gate check-integration-full $(TESTGATE_JOBS)

## check-campaign: Level 4 local deterministic/campaign prerequisites; scheduled CI adds bounded live Qwen work
.PHONY: check-campaign
check-campaign:
	$(TESTGATE) run --gate check-campaign $(TESTGATE_JOBS)

## check-dgx: run the explicit read-only DGX safety preflight; task-specific qualification remains required
.PHONY: check-dgx
check-dgx:
	$(TESTGATE) run --gate check-dgx --jobs 1

## check-dgx-smoke: run one risk-selected DGX profile with one preflight/build/transfer (requires explicit values)
.PHONY: check-dgx-smoke
check-dgx-smoke:
	@test -n "$(DGX_PROFILE)" || { echo "check-dgx-smoke: DGX_PROFILE=<preflight|cookie|enforcement|kernel-full|stack> is required"; exit 2; }
	@test -n "$(RUN_ID)" || { echo "check-dgx-smoke: RUN_ID=<bounded-run-id> is required"; exit 2; }
	scripts/dgx/pr.sh --profile "$(DGX_PROFILE)" --run-id "$(RUN_ID)"

## check-merge: final tier-aware proof; non-local tiers fail closed pending a task-specific DGX check ID
.PHONY: check-merge
check-merge:
	@case "$(VALIDATION_TIER)" in \
	local) $(MAKE) check-merge-local ;; \
	*) $(MAKE) check-merge-local && $(MAKE) check-dgx; \
	   echo "check-merge: $(VALIDATION_TIER) also requires the task-specific DGX/Kubernetes/attacker qualification and recorded artifact; generic preflight cannot qualify it." >&2; exit 2 ;; \
	esac

## check-report: print the most recent durable gate summary and reproduction commands
.PHONY: check-report
check-report:
	$(TESTGATE) report

.PHONY: check-ci-go check-ci-frontend check-ci-ebpf check-ci-ebpf-privileged check-ci-adversarial
check-ci-go:
	$(TESTGATE) run --gate ci-go $(TESTGATE_JOBS)
check-ci-frontend:
	$(TESTGATE) run --gate ci-frontend $(TESTGATE_JOBS)
check-ci-ebpf:
	$(TESTGATE) run --gate ci-ebpf $(TESTGATE_JOBS)
check-ci-ebpf-privileged:
	GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$(CURDIR)" \
		$(TESTGATE) run --gate ci-ebpf-privileged --jobs 1
check-ci-adversarial:
	$(TESTGATE) run --gate ci-adversarial $(TESTGATE_JOBS)

## check: compatibility alias for the recommended Level 1 local PR precheck
.PHONY: check
check: check-pr-local

## proto: regenerate committed protobuf Go output with pinned tool versions
.PHONY: proto
proto:
	@./scripts/generated.sh write proto

## operator-generate: regenerate committed Kubernetes deepcopy and CRD output
.PHONY: operator-generate
operator-generate:
	@./scripts/generated.sh write operator

## generated: regenerate all committed protobuf and Kubernetes output
.PHONY: generated
generated:
	@./scripts/generated.sh write all

## generated-check: fail when committed protobuf or Kubernetes output has drifted
.PHONY: generated-check
generated-check:
	@./scripts/generated.sh check all

## bpf: compile the eBPF kernel programs with clang (real work on Linux only)
.PHONY: bpf
bpf:
ifneq ($(UNAME_S),Linux)
	@echo "bpf: skipping native eBPF object build on $(UNAME_S) — clang/bpf codegen is exercised on Linux/CI."
	@echo "bpf: (the engine, sting userspace, and tests are platform-independent; develop those here.)"
else
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "bpf: clang not found — install clang/llvm + libbpf headers."; exit 1; }
	@if [ -z "$(strip $(BPF_SRC))" ]; then echo "bpf: no eBPF sources found under bpf/{enforce,observe,sockops}."; exit 0; fi
	@$(MAKE) $(BPF_OBJ)
	@echo "bpf: built $(BPF_OBJ)"
endif

.PHONY: bpf-object-check
bpf-object-check:
	@for src in $(BPF_SRC); do \
		obj="$${src%.bpf.c}.bpf.o"; \
		test -s "$$obj" || { echo "missing compiled object for $$src: $$obj"; exit 1; }; \
	done

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
