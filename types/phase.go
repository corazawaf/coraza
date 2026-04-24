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
	// PhaseUnknown represents a phase unrecognized by Coraza
	PhaseUnknown RulePhase = 0
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

// String returns a short stable identifier for the phase, suitable for use
// as a metric label or log key.
func (p RulePhase) String() string {
	switch p {
	case PhaseRequestHeaders:
		return "request_headers"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeaders:
		return "response_headers"
	case PhaseResponseBody:
		return "response_body"
	case PhaseLogging:
		return "logging"
	}
	return "unknown"
}

// ParseRulePhase parses the phase of the rule from a to 5
// or request:2, response:4, logging:5
// if the phase is invalid it will return an error
func ParseRulePhase(phase string) (RulePhase, error) {
	var i int
	switch phase {
	case "request":
		i = 2
	case "response":
		i = 4
	case "logging":
		i = 5
	default:
		// When phase parsing fails, will be 0,
		// so there is no need to judge error.
		i, _ = strconv.Atoi(phase)
	}
	if i > 5 || i < 1 {
		return PhaseUnknown, fmt.Errorf("invalid phase %s", phase)
	}
	return RulePhase(i), nil
}
