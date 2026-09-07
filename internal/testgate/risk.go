package testgate

import (
	"fmt"
	"sort"
	"strings"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskStandard RiskLevel = "STANDARD"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

type RiskReason struct {
	Path   string    `json:"path"`
	Level  RiskLevel `json:"level"`
	Reason string    `json:"reason"`
}

type RiskReport struct {
	Automatic           RiskLevel    `json:"automatic"`
	Effective           RiskLevel    `json:"effective"`
	ManualOverride      RiskLevel    `json:"manual_override,omitempty"`
	OverrideDisposition string       `json:"override_disposition,omitempty"`
	Executable          bool         `json:"executable"`
	ChangedFiles        []string     `json:"changed_files"`
	Reasons             []RiskReason `json:"reasons"`
	RemoteProfiles      []string     `json:"remote_profiles,omitempty"`
	RequiresPrivileged  bool         `json:"requires_privileged"`
	RequiresDGX         bool         `json:"requires_dgx"`
	RequiresLiveQwen    bool         `json:"requires_live_qwen"`
	FrontendAffected    bool         `json:"frontend_affected"`
	EBPFAffected        bool         `json:"ebpf_affected"`
	GateAffected        bool         `json:"gate_affected"`
}

func ParseRiskLevel(value string) (RiskLevel, error) {
	level := RiskLevel(strings.ToUpper(strings.TrimSpace(value)))
	if level == "" {
		return "", nil
	}
	if riskRank(level) == 0 {
		return "", fmt.Errorf("risk must be LOW, STANDARD, HIGH, or CRITICAL")
	}
	return level, nil
}

func ClassifyRisk(files []string, manual string) (RiskReport, error) {
	report := RiskReport{Automatic: RiskLow, Effective: RiskLow, ChangedFiles: append([]string(nil), files...)}
	profiles := make(map[string]bool)
	if len(files) == 0 {
		report.Reasons = append(report.Reasons, RiskReason{Level: RiskLow, Reason: "no changed paths; structural light profile"})
	}
	for _, path := range files {
		level, reason, executable := classifyPath(path)
		report.Reasons = append(report.Reasons, RiskReason{Path: path, Level: level, Reason: reason})
		if riskRank(level) > riskRank(report.Automatic) {
			report.Automatic = level
		}
		report.Executable = report.Executable || executable
		if isFrontendPath(path) {
			report.FrontendAffected = true
		}
		switch {
		case isAttackerLoopPath(path):
			profiles["dgx-attacker-loop"] = true
			report.RequiresLiveQwen = true
		case strings.HasPrefix(path, "internal/canaryattacker/executor/"), strings.HasPrefix(path, "cmd/attackerexecutorspike/"):
			profiles["dgx-attacker-executor"] = true
		case strings.HasPrefix(path, "cmd/tracespike/"):
			profiles["dgx-trace"] = true
		case strings.HasPrefix(path, "bpf/"):
			report.EBPFAffected = true
			report.RequiresPrivileged = true
			profiles["dgx-kernel"] = true
		case strings.HasPrefix(path, "internal/sting/containment/"):
			report.RequiresPrivileged = true
			profiles["dgx-enforcement"] = true
		case strings.HasPrefix(path, "scripts/dgx/"):
			switch {
			case strings.Contains(path, "attackerloopspike"):
				profiles["dgx-attacker-loop"] = true
				report.RequiresLiveQwen = true
			case strings.Contains(path, "attackerexecutorspike"):
				profiles["dgx-attacker-executor"] = true
			case strings.Contains(path, "tracespike"):
				profiles["dgx-trace"] = true
			case strings.Contains(path, "attackercheck"):
				profiles["dgx-attacker-check"] = true
			case strings.Contains(path, "cookiespike"), strings.Contains(path, "enforcespike"),
				strings.HasSuffix(path, "/cleanup.sh"), strings.HasSuffix(path, "/pr.sh"),
				strings.HasSuffix(path, "/preflight-proof.sh"):
				profiles["dgx-kernel"] = true
			default:
				profiles["dgx-harness"] = true
			}
		case strings.HasPrefix(path, "internal/identity/"), strings.HasPrefix(path, "internal/operator/"), strings.HasPrefix(path, "deploy/"), strings.HasPrefix(path, "config/"):
			profiles["dgx-kubernetes"] = true
		case strings.HasPrefix(path, "internal/llm/attacker/"), strings.HasPrefix(path, "cmd/llm-attacker/"):
			profiles["dgx-attacker-smoke"] = true
			report.RequiresLiveQwen = true
		}
		if isGatePath(path) {
			report.GateAffected = true
		}
	}
	report.Effective = report.Automatic
	override, err := ParseRiskLevel(manual)
	if err != nil {
		return RiskReport{}, err
	}
	if override != "" {
		report.ManualOverride = override
		if riskRank(override) > riskRank(report.Automatic) {
			report.Effective = override
			report.OverrideDisposition = "increased automatic classification"
		} else if riskRank(override) == riskRank(report.Automatic) {
			report.OverrideDisposition = "matched automatic classification"
		} else {
			report.OverrideDisposition = "ignored because manual overrides cannot reduce automatic coverage"
		}
	}
	if report.Effective == RiskCritical && len(profiles) == 0 {
		profiles["dgx-manual-critical"] = true
	}
	for profile := range profiles {
		report.RemoteProfiles = append(report.RemoteProfiles, profile)
	}
	sort.Strings(report.RemoteProfiles)
	report.RequiresDGX = len(report.RemoteProfiles) > 0
	return report, nil
}

func classifyPath(path string) (RiskLevel, string, bool) {
	path = strings.TrimPrefix(strings.TrimSpace(path), "./")
	switch {
	case path == "":
		return RiskHigh, "empty or unknown path defaults to HIGH", true
	case isAttackerLoopPath(path):
		return RiskCritical, "untrusted live-model planner and attacker execution safety boundary", true
	case strings.HasPrefix(path, "internal/canaryattacker/executor/"), strings.HasPrefix(path, "cmd/attackerexecutorspike/"):
		return RiskCritical, "bounded attacker execution authority and network safety boundary", true
	case strings.HasPrefix(path, "internal/canaryattacker/"):
		return RiskHigh, "synthetic adversary contract and ground-truth isolation boundary", true
	case strings.HasPrefix(path, "bpf/"), strings.HasPrefix(path, "scripts/dgx/"), strings.HasPrefix(path, "cmd/tracespike/"),
		strings.HasPrefix(path, "internal/sting/containment/"), strings.HasPrefix(path, "bpf/sockops/"),
		strings.HasPrefix(path, "internal/llm/attacker/"), strings.HasPrefix(path, "cmd/llm-attacker/"):
		return RiskCritical, "kernel, containment, DGX, or attacker-tool safety boundary", true
	case isGatePath(path):
		return RiskHigh, "test-gate orchestration changes require broad Level 2 validation", true
	case strings.HasPrefix(path, "internal/contract/"), strings.HasPrefix(path, "internal/identity/"),
		strings.HasPrefix(path, "internal/engine/"), strings.HasPrefix(path, "internal/sting/"),
		strings.HasPrefix(path, "adapters/"), strings.HasPrefix(path, "internal/operator/"),
		strings.HasPrefix(path, "deploy/"), strings.HasPrefix(path, "config/"),
		strings.HasPrefix(path, "api/proto/"):
		return RiskHigh, "shared security, identity, scope, trigger, adapter, or deployment surface", true
	case strings.HasPrefix(path, "docs/"), path == "AGENTS.md", path == ".gitignore",
		strings.HasSuffix(path, ".md"), strings.HasPrefix(path, "presentations/"), strings.HasPrefix(path, "slides/"):
		return RiskLow, "prose or non-executable development material", false
	case strings.HasPrefix(path, "dashboard/app/"), strings.HasSuffix(path, ".go"),
		path == "go.mod", path == "go.sum", strings.HasPrefix(path, "scripts/"):
		return RiskStandard, "ordinary executable, UI, generated, or unit-test surface", true
	default:
		return RiskHigh, "unmapped path defaults conservatively to HIGH", true
	}
}

func isAttackerLoopPath(path string) bool {
	return strings.HasPrefix(path, "internal/canaryattacker/planner/") ||
		strings.HasPrefix(path, "internal/canaryattacker/ollama/") ||
		strings.HasPrefix(path, "cmd/attackerloopspike/")
}

func isGatePath(path string) bool {
	return path == "Makefile" || strings.HasPrefix(path, ".github/workflows/") ||
		strings.HasPrefix(path, "internal/testgate/") || strings.HasPrefix(path, "cmd/testgate/") ||
		strings.HasPrefix(path, "test/gates/") || strings.HasPrefix(path, ".agents/skills/canarysting-dev/")
}

func riskRank(level RiskLevel) int {
	switch level {
	case RiskLow:
		return 1
	case RiskStandard:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	default:
		return 0
	}
}
