// Package testgate implements CanaryPlatform's repository-local validation DAG.
// It is development infrastructure only; it is not linked into product binaries.
package testgate

import "time"

type Manifest struct {
	Version int     `json:"version"`
	Checks  []Check `json:"checks"`
}

type Check struct {
	ID                    string            `json:"id"`
	Label                 string            `json:"label"`
	Command               []string          `json:"command"`
	Dependencies          []string          `json:"dependencies,omitempty"`
	Gates                 []string          `json:"gates"`
	Timeout               string            `json:"timeout"`
	Privilege             string            `json:"privilege"`
	IsolationKey          string            `json:"isolation_key"`
	ConcurrencyGroup      string            `json:"concurrency_group"`
	FailureClass          string            `json:"failure_class"`
	ResultParser          string            `json:"result_parser,omitempty"`
	Cleanup               []string          `json:"cleanup,omitempty"`
	CleanupSafetyCritical bool              `json:"cleanup_safety_critical,omitempty"`
	SafetyCritical        bool              `json:"safety_critical,omitempty"`
	Platforms             []string          `json:"platforms,omitempty"`
	Replay                string            `json:"replay"`
	ManualRecovery        string            `json:"manual_recovery,omitempty"`
	Tags                  []string          `json:"tags,omitempty"`
	Scenario              *ScenarioMetadata `json:"scenario,omitempty"`
}

type ScenarioManifest struct {
	Version   int        `json:"version"`
	Scenarios []Scenario `json:"scenarios"`
}

type Scenario struct {
	ID                   string            `json:"id"`
	Title                string            `json:"title"`
	Objective            string            `json:"objective"`
	TargetScope          string            `json:"target_scope"`
	RequiredBinaries     []string          `json:"required_binaries"`
	RequiredServices     []string          `json:"required_services"`
	RequiredPrivileges   string            `json:"required_privileges"`
	AllowedHosts         []string          `json:"allowed_hosts"`
	AllowedPorts         []int             `json:"allowed_ports"`
	Fixtures             []string          `json:"fixtures"`
	DeterministicSeed    int64             `json:"deterministic_seed"`
	Setup                []string          `json:"setup"`
	Actions              []string          `json:"actions"`
	ExpectedObservations []string          `json:"expected_observations"`
	ExpectedCanaryView   []string          `json:"expected_canaryview_evidence"`
	ExpectedCanarySting  []string          `json:"expected_canarysting_behavior"`
	ProhibitedOutcomes   []string          `json:"prohibited_outcomes"`
	Timeout              string            `json:"timeout"`
	Cleanup              []string          `json:"cleanup"`
	AfterStateAssertions []string          `json:"after_state_assertions"`
	IsolationKey         string            `json:"concurrency_isolation_key"`
	Replay               string            `json:"direct_replay_command"`
	Command              []string          `json:"command"`
	Dependencies         []string          `json:"dependencies"`
	FailureClass         string            `json:"failure_class"`
	SafetyCritical       bool              `json:"safety_critical,omitempty"`
	AttackerIntent       string            `json:"attacker_intent"`
	AttackerAction       string            `json:"attacker_action"`
	GroundTruth          map[string]string `json:"ground_truth"`
	RequiredTestPasses   []string          `json:"required_test_passes"`
}

type ScenarioMetadata struct {
	ManifestVersion    int               `json:"scenario_version"`
	DeterministicSeed  int64             `json:"deterministic_seed"`
	AttackerIntent     string            `json:"attacker_intent"`
	AttackerAction     string            `json:"attacker_action"`
	ExpectedEvidence   []string          `json:"expected_evidence"`
	ObservedEvidence   []string          `json:"observed_evidence"`
	MissingEvidence    []string          `json:"missing_evidence"`
	IncorrectJoins     []string          `json:"incorrect_joins"`
	IdentityResult     string            `json:"identity_result"`
	CorrelationResult  string            `json:"correlation_result"`
	ResponseResult     string            `json:"response_result"`
	CleanupResult      string            `json:"cleanup_result"`
	GroundTruth        map[string]string `json:"ground_truth"`
	RequiredAssertions []string          `json:"required_assertions"`
}

type Status string

const (
	StatusPass       Status = "PASS"
	StatusFail       Status = "FAIL"
	StatusBlocked    Status = "BLOCKED"
	StatusSkipped    Status = "SKIPPED"
	StatusSafetyStop Status = "SAFETY STOP"
)

type Result struct {
	ID              string            `json:"id"`
	Label           string            `json:"label"`
	Status          Status            `json:"status"`
	FailureClass    string            `json:"failure_class,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Duration        time.Duration     `json:"-"`
	DurationSeconds float64           `json:"duration_seconds"`
	StartedAt       time.Time         `json:"started_at,omitempty"`
	FinishedAt      time.Time         `json:"finished_at,omitempty"`
	Replay          string            `json:"replay"`
	LogPath         string            `json:"log_path,omitempty"`
	CleanupStatus   string            `json:"cleanup_status,omitempty"`
	Cache           string            `json:"cache"`
	ExitCode        int               `json:"exit_code,omitempty"`
	Retry           *RetryResult      `json:"retry,omitempty"`
	Scenario        *ScenarioMetadata `json:"scenario,omitempty"`
}

type RetryResult struct {
	Status          Status  `json:"status"`
	DurationSeconds float64 `json:"duration_seconds"`
	LogPath         string  `json:"log_path"`
	CleanupStatus   string  `json:"cleanup_status"`
}

type Fingerprint struct {
	SourceRevision string   `json:"source_revision"`
	MergeBase      string   `json:"merge_base,omitempty"`
	WorkingTree    string   `json:"working_tree_fingerprint"`
	Toolchain      string   `json:"toolchain_fingerprint"`
	Manifest       string   `json:"manifest_fingerprint"`
	Environment    string   `json:"environment_fingerprint"`
	ChangedFiles   []string `json:"changed_files"`
}

type Summary struct {
	RunID             string              `json:"run_id"`
	ParentRunID       string              `json:"parent_run_id,omitempty"`
	Gate              string              `json:"gate"`
	StartedAt         time.Time           `json:"started_at"`
	FinishedAt        time.Time           `json:"finished_at"`
	DurationSeconds   float64             `json:"duration_seconds"`
	Fingerprint       Fingerprint         `json:"fingerprint"`
	Results           []Result            `json:"results"`
	Counts            map[Status]int      `json:"counts"`
	CacheHits         int                 `json:"cache_hits"`
	CacheMisses       int                 `json:"cache_misses"`
	SafetyStop        bool                `json:"safety_stop"`
	Compatibility     string              `json:"compatibility,omitempty"`
	ReplayChanges     map[string][]string `json:"replay_changes,omitempty"`
	ArtifactDirectory string              `json:"artifact_directory"`
}

type RunOptions struct {
	Gate                  string
	OnlyChecks            []string
	Jobs                  int
	RetryFailures         bool
	ArtifactRoot          string
	ParentRunID           string
	Compatibility         string
	ParentStatuses        map[string]Status
	CompleteFailureReplay bool
}
