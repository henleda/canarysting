package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/canarysting/canarysting/internal/canaryattacker/executor"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

const (
	Version                     = "bounded-qwen-planner-v1"
	AbsoluteMaxTurns            = 64
	AbsoluteMaxOutputTokens     = 2048
	AbsoluteMaxContextTokens    = 32768
	AbsoluteMaxObservationBytes = 16 << 10
	AbsoluteMaxProposalBytes    = 4 << 10
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type StopReason string

const (
	StopScenarioComplete StopReason = "scenario_complete"
	StopModel            StopReason = "model_stop"
	StopMaxTurns         StopReason = "max_turns"
	StopActionBudget     StopReason = "action_budget"
	StopTokenBudget      StopReason = "token_budget"
	StopCancelled        StopReason = "cancelled"
	StopModelError       StopReason = "model_error"
	StopExecutorError    StopReason = "executor_error"
)

var (
	ErrInvalidModelResponse = errors.New("invalid model response")
	ErrModelBudget          = errors.New("model response exceeded the external budget")
)

type Tool struct {
	Name        string
	Description string
}

type Observation struct {
	ToolName         string `json:"tool_name"`
	Status           string `json:"status"`
	ErrorCode        string `json:"error_code,omitempty"`
	HTTPStatus       uint16 `json:"http_status,omitempty"`
	ResponseBytes    uint64 `json:"response_bytes,omitempty"`
	ResponseRef      string `json:"response_ref,omitempty"`
	ContentBase64    string `json:"content_base64,omitempty"`
	ContentTruncated bool   `json:"content_truncated,omitempty"`
}

type TurnRequest struct {
	Model           string
	Instruction     string
	Tools           []Tool
	Observations    []Observation
	MaxOutputTokens uint64
	ContextTokens   uint64
	MaxProposals    uint32
	Seed            int64
}

type Proposal struct {
	Name      string
	Arguments json.RawMessage
}

type TurnResponse struct {
	Model        string
	Done         bool
	DoneReason   string
	PromptTokens uint64
	OutputTokens uint64
	OutputSHA256 string
	Proposals    []Proposal
}

type Client interface {
	Complete(context.Context, TurnRequest) (TurnResponse, error)
}

type ActionExecutor interface {
	Execute(context.Context, executor.Invocation) (executor.Execution, error)
}

type Config struct {
	Scenario groundtruth.Scenario
	Model    groundtruth.ModelIdentity
	Client   Client
	Executor ActionExecutor
	MaxTurns uint32
	Seed     int64
}

type Result struct {
	StopReason      StopReason
	TurnsCompleted  uint32
	ProposalsLogged uint32
	Approved        uint32
	Denied          uint32
	PromptTokens    uint64
	OutputTokens    uint64
	Executions      []executor.Execution
}

type Coordinator struct {
	scenario groundtruth.Scenario
	model    groundtruth.ModelIdentity
	client   Client
	executor ActionExecutor
	maxTurns uint32
	seed     int64
	catalog  []catalogAction
}

type catalogAction struct {
	name      string
	stepIndex int
	step      groundtruth.Step
	action    groundtruth.ActionSpec
}

func New(config Config) (*Coordinator, error) {
	if config.Client == nil || config.Executor == nil {
		return nil, fmt.Errorf("planner client and executor are required")
	}
	if _, err := groundtruth.NewModelIdentity(groundtruth.ModelIdentityInput{
		AttackerID: config.Model.AttackerID(), Provider: config.Model.Provider(), Model: config.Model.Model(),
		ModelVersion: config.Model.ModelVersion(), PlannerVersion: config.Model.PlannerVersion(),
	}); err != nil {
		return nil, fmt.Errorf("model identity: %w", err)
	}
	if config.Model.PlannerVersion() != Version {
		return nil, fmt.Errorf("model identity must pin planner version %q", Version)
	}
	steps := config.Scenario.Steps()
	budgets := config.Scenario.Budgets()
	if len(steps) == 0 || budgets.MaxActions() == 0 || budgets.MaxModelTokens() == 0 {
		return nil, fmt.Errorf("scenario must carry reviewed steps and external budgets")
	}
	if config.MaxTurns == 0 || config.MaxTurns > AbsoluteMaxTurns || config.MaxTurns > budgets.MaxActions() {
		return nil, fmt.Errorf("max turns must be between 1 and min(%d, scenario max actions)", AbsoluteMaxTurns)
	}
	catalog := make([]catalogAction, 0)
	ordinal := 1
	for stepIndex, step := range steps {
		for _, action := range step.AllowedActions() {
			catalog = append(catalog, catalogAction{
				name: fmt.Sprintf("action_%03d", ordinal), stepIndex: stepIndex, step: step, action: action,
			})
			ordinal++
		}
	}
	return &Coordinator{
		scenario: config.Scenario, model: config.Model, client: config.Client,
		executor: config.Executor, maxTurns: config.MaxTurns, seed: config.Seed, catalog: catalog,
	}, nil
}

func validateResponse(response TurnResponse, request TurnRequest) error {
	if response.Model != request.Model || !response.Done {
		return fmt.Errorf("%w: model identity or completion marker mismatch", ErrInvalidModelResponse)
	}
	if response.PromptTokens == 0 || response.OutputTokens == 0 || response.OutputTokens > request.MaxOutputTokens {
		return fmt.Errorf("%w: token usage is absent or exceeds the per-turn ceiling", ErrInvalidModelResponse)
	}
	if !sha256Pattern.MatchString(response.OutputSHA256) {
		return fmt.Errorf("%w: output digest is not a canonical SHA-256", ErrInvalidModelResponse)
	}
	if len(response.Proposals) > int(request.MaxProposals) {
		return fmt.Errorf("%w: proposal count exceeds remaining action capacity", ErrInvalidModelResponse)
	}
	if len(response.DoneReason) > 64 {
		return fmt.Errorf("%w: done reason is oversized", ErrInvalidModelResponse)
	}
	for _, proposal := range response.Proposals {
		if len(proposal.Name) == 0 || len(proposal.Name) > 128 || len(proposal.Arguments) > AbsoluteMaxProposalBytes {
			return fmt.Errorf("%w: proposal fields are absent or oversized", ErrInvalidModelResponse)
		}
		if !json.Valid(proposal.Arguments) {
			return fmt.Errorf("%w: proposal arguments are not JSON", ErrInvalidModelResponse)
		}
	}
	return nil
}

func min64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}

func emittedNow() time.Time { return time.Now().UTC() }
