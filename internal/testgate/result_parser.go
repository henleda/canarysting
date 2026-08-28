package testgate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

type goTestEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
}

func applyResultParser(check Check, output []byte, result *Result) {
	if check.ResultParser != "go-test-json-required-passes" {
		return
	}
	requiredAssertions := check.RequiredTestPasses
	if len(requiredAssertions) == 0 && result.Scenario != nil {
		requiredAssertions = result.Scenario.RequiredAssertions
	}
	required := make(map[string]bool, len(requiredAssertions))
	for _, name := range requiredAssertions {
		required[name] = false
	}
	var parseErrors []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event goTestEvent
		if err := json.Unmarshal(line, &event); err != nil {
			parseErrors = append(parseErrors, err.Error())
			continue
		}
		if event.Action == "pass" {
			if _, ok := required[event.Test]; ok {
				required[event.Test] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		parseErrors = append(parseErrors, err.Error())
	}
	for name, passed := range required {
		if result.Scenario != nil {
			if passed {
				result.Scenario.ObservedEvidence = append(result.Scenario.ObservedEvidence, "test-pass:"+name)
			} else {
				result.Scenario.MissingEvidence = append(result.Scenario.MissingEvidence, "test-pass:"+name)
			}
		}
	}
	missing := make([]string, 0)
	for name, passed := range required {
		if !passed {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if result.Scenario != nil {
		sort.Strings(result.Scenario.ObservedEvidence)
		sort.Strings(result.Scenario.MissingEvidence)
	}
	if len(parseErrors) > 0 || len(missing) > 0 {
		if result.Status != StatusSafetyStop {
			result.Status = StatusFail
			result.FailureClass = "test defect"
			if len(parseErrors) > 0 {
				result.Reason = fmt.Sprintf("scenario result parser rejected %d malformed event(s)", len(parseErrors))
			} else {
				result.Reason = "required test assertions did not report PASS: " + fmt.Sprint(missing)
			}
		}
	}
}
