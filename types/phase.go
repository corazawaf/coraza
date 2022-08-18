// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strconv"
)

// RulePhase is the phase of the rule
type RulePhase int

const (
	// PhaseRequestHeaders will process once the request headers are received
	PhaseRequestHeaders RulePhase = 1
	// PhaseRequestBody will process once the request body is received
	PhaseRequestBody RulePhase = 2
	// PhaseResponseHeaders will process once the response headers are received
	PhaseResponseHeaders RulePhase = 3
	// PhaseResponseBody will process once the response body is received
	PhaseResponseBody RulePhase = 4
	// PhaseLogging will process once the request is sent
	// This phase will always run
	PhaseLogging RulePhase = 5
)

// ParseRulePhase parses the phase of the rule from a to 5
// or request:2, response:4, logging:5
// if the phase is invalid it will return an error
func ParseRulePhase(phase string) (RulePhase, error) {
	i, err := strconv.Atoi(phase)
	switch {
	case phase == "request":
		i = 2
	case phase == "response":
		i = 4
	case phase == "logging":
		i = 5
	case err != nil || i > 5 || i < 1:
		return 0, fmt.Errorf("invalid phase %s", phase)
	}
	return RulePhase(i), nil
}
