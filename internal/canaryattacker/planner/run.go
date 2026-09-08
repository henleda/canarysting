package planner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/canarysting/canarysting/internal/canaryattacker/executor"
	"github.com/canarysting/canarysting/internal/canaryattacker/groundtruth"
)

const fixedInstruction = "Operate only through one available zero-argument action function. The coordinator owns every target, operation, fixture, credential, policy, and budget. Do not invent arguments. Return no function call only when no reviewed action should run."

func (c *Coordinator) Run(ctx context.Context) (Result, error) {
	result := Result{Executions: make([]executor.Execution, 0)}
	steps := c.scenario.Steps()
	budgets := c.scenario.Budgets()
	runCtx, cancel := context.WithTimeout(ctx, budgets.MaxDuration())
	defer cancel()

	stepIndex := 0
	observations := make([]Observation, 0)
	for turn := uint32(0); turn < c.maxTurns; turn++ {
		if runCtx.Err() != nil {
			result.StopReason = StopCancelled
			return result, nil
		}
		if stepIndex >= len(steps) {
			result.StopReason = StopScenarioComplete
			return result, nil
		}
		if result.ProposalsLogged >= budgets.MaxActions() {
			result.StopReason = StopActionBudget
			return result, nil
		}
		if len(observations) >= AbsoluteMaxObservations {
			result.StopReason = StopObservationBudget
			return result, nil
		}
		if observationHistoryBytes(observations) > AbsoluteMaxObservationHistoryBytes {
			result.StopReason = StopObservationBudget
			return result, nil
		}
		usedTokens := result.PromptTokens + result.OutputTokens
		if usedTokens >= budgets.MaxModelTokens() {
			result.StopReason = StopTokenBudget
			return result, nil
		}
		remainingTokens := budgets.MaxModelTokens() - usedTokens
		contextTokens, outputTokens, ok := turnTokenLimits(remainingTokens)
		if !ok {
			result.StopReason = StopTokenBudget
			return result, nil
		}
		request := TurnRequest{
			Model: c.model.Model(), Instruction: fixedInstruction,
			Tools: c.toolsForStep(stepIndex), Observations: append([]Observation(nil), observations...),
			MaxOutputTokens: outputTokens,
			ContextTokens:   contextTokens,
			MaxProposals:    min32(budgets.MaxActions()-result.ProposalsLogged, uint32(AbsoluteMaxObservations-len(observations))),
			Seed:            c.seed,
		}
		response, err := c.client.Complete(runCtx, request)
		if err != nil {
			if runCtx.Err() != nil {
				result.StopReason = StopCancelled
				return result, nil
			}
			result.StopReason = StopModelError
			return result, fmt.Errorf("planner turn %d: %w", turn+1, err)
		}
		result.TurnsCompleted++
		if err := validateResponse(response, request); err != nil {
			result.StopReason = StopModelError
			return result, err
		}
		turnTokens := response.PromptTokens + response.OutputTokens
		if turnTokens < response.PromptTokens || turnTokens > remainingTokens {
			result.StopReason = StopTokenBudget
			return result, ErrModelBudget
		}
		result.PromptTokens += response.PromptTokens
		result.OutputTokens += response.OutputTokens
		if len(response.Proposals) == 0 {
			result.StopReason = StopModel
			return result, nil
		}

		activeStep := stepIndex
		acceptedThisTurn := false
		for proposalIndex, proposal := range response.Proposals {
			selected, accepted := c.selectAction(activeStep, proposal, proposalIndex == 0)
			if !accepted {
				var rejectErr error
				selected, rejectErr = rejectedAction(steps[activeStep])
				if rejectErr != nil {
					result.StopReason = StopExecutorError
					return result, rejectErr
				}
			}
			execution, executeErr := c.executor.Execute(runCtx, executor.Invocation{
				StepID: steps[activeStep].ID(), Objective: steps[activeStep].Objective(), Model: c.model,
				ProposedAction: selected, EmittedAt: emittedNow(),
				PlannerOutputRef: "planner:sha256:" + response.OutputSHA256,
			})
			if executeErr != nil {
				result.StopReason = StopExecutorError
				return result, fmt.Errorf("execute proposal %d on turn %d: %w", proposalIndex+1, turn+1, executeErr)
			}
			result.ProposalsLogged++
			result.Executions = append(result.Executions, execution)
			if execution.Result.Status == groundtruth.ActionDenied {
				result.Denied++
			} else {
				result.Approved++
			}
			observationName := proposal.Name
			if !accepted {
				observationName = "proposal_rejected"
			}
			observations = append(observations, observation(observationName, execution.Result))
			if accepted {
				acceptedThisTurn = true
			}
		}
		if acceptedThisTurn {
			stepIndex++
		}
		if runCtx.Err() != nil {
			result.StopReason = StopCancelled
			return result, nil
		}
	}
	if stepIndex >= len(steps) {
		result.StopReason = StopScenarioComplete
	} else if result.ProposalsLogged >= budgets.MaxActions() {
		result.StopReason = StopActionBudget
	} else {
		result.StopReason = StopMaxTurns
	}
	return result, nil
}

func observationHistoryBytes(observations []Observation) int {
	encoded, err := json.Marshal(observations)
	if err != nil {
		return AbsoluteMaxObservationHistoryBytes + 1
	}
	return len(encoded)
}

func min32(left, right uint32) uint32 {
	if left < right {
		return left
	}
	return right
}

func (c *Coordinator) toolsForStep(stepIndex int) []Tool {
	tools := make([]Tool, 0)
	for _, item := range c.catalog {
		if item.stepIndex != stepIndex {
			continue
		}
		tools = append(tools, Tool{
			Name:        item.name,
			Description: fmt.Sprintf("Execute reviewed synthetic action %s for scenario step %s.", item.name, item.step.ID()),
		})
	}
	return tools
}

func (c *Coordinator) selectAction(stepIndex int, proposal Proposal, first bool) (groundtruth.ActionSpec, bool) {
	if !first || !emptyArguments(proposal.Arguments) {
		return groundtruth.ActionSpec{}, false
	}
	for _, item := range c.catalog {
		if item.stepIndex == stepIndex && item.name == proposal.Name {
			return item.action, true
		}
	}
	return groundtruth.ActionSpec{}, false
}

func emptyArguments(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false
	}
	return object != nil && len(object) == 0
}

func turnTokenLimits(remaining uint64) (contextTokens, outputTokens uint64, ok bool) {
	if remaining < 2 {
		return 0, 0, false
	}
	outputTokens = min64(remaining/2, AbsoluteMaxOutputTokens)
	contextTokens = min64(remaining-outputTokens, AbsoluteMaxContextTokens)
	return contextTokens, outputTokens, contextTokens > 0 && outputTokens > 0
}

func rejectedAction(step groundtruth.Step) (groundtruth.ActionSpec, error) {
	base := step.AllowedActions()[0]
	action, err := groundtruth.NewActionSpec(groundtruth.ActionSpecInput{
		Tool: "planner_rejected", TargetAlias: base.TargetAlias(), TargetRef: base.TargetRef(), Operation: "proposal_rejected",
	})
	if err != nil {
		return groundtruth.ActionSpec{}, fmt.Errorf("construct rejected proposal audit action: %w", err)
	}
	return action, nil
}

func observation(toolName string, result executor.Result) Observation {
	content := result.Content
	truncated := false
	if len(content) > AbsoluteMaxObservationBytes {
		content = content[:AbsoluteMaxObservationBytes]
		truncated = true
	}
	return Observation{
		ToolName: toolName, Status: string(result.Status), ErrorCode: result.ErrorCode,
		HTTPStatus: result.HTTPStatus, ResponseBytes: result.ResponseBytes, ResponseRef: result.ResponseRef,
		ContentBase64: base64.StdEncoding.EncodeToString(content), ContentTruncated: truncated,
	}
}
