package types

import (
	"fmt"
	"strconv"
)

type RulePhase int

const (
	PhaseRequestHeaders  RulePhase = 1
	PhaseRequestBody     RulePhase = 2
	PhaseResponseHeaders RulePhase = 3
	PhaseResponseBody    RulePhase = 4
	PhaseLogging         RulePhase = 5
)

// ParseRulePhase parses the phase of the rule from a to 5
// or request:2, response:4, logging:5
// if the phase is invalid it will return an error
func ParseRulePhase(phase string) (RulePhase, error) {
	i, err := strconv.Atoi(phase)
	if phase == "request" {
		i = 2
	} else if phase == "response" {
		i = 4
	} else if phase == "logging" {
		i = 5
	} else if err != nil || i > 5 || i < 1 {
		return 0, fmt.Errorf("invalid phase %s", phase)
	}
	return RulePhase(i), nil
}
