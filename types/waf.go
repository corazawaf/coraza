// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"strings"
)

// AuditEngineStatus represents the functionality
// of the audit engine.
type AuditEngineStatus int

const (
	// AuditEngineOn will audit each auditable event
	AuditEngineOn AuditEngineStatus = iota
	// AuditEngineOff will not audit any event
	AuditEngineOff AuditEngineStatus = iota
	// AuditEngineRelevantOnly will audit only relevant events
	AuditEngineRelevantOnly AuditEngineStatus = iota
)

// ParseAuditEngineStatus parses the audit engine status
func ParseAuditEngineStatus(as string) (AuditEngineStatus, error) {
	switch strings.ToLower(as) {
	case "on":
		return AuditEngineOn, nil
	case "off":
		return AuditEngineOff, nil
	case "relevantonly":
		return AuditEngineRelevantOnly, nil
	}
	return -1, fmt.Errorf("invalid audit engine status: %s", as)
}

// RuleEngineStatus represents the functionality
// of the rule engine.
type RuleEngineStatus int

const (
	// RuleEngineOn will process each rule and may generate
	// disruptive actions
	RuleEngineOn RuleEngineStatus = iota
	// RuleEngineDetectionOnly will process each rule but won't
	// generate disruptive actions
	RuleEngineDetectionOnly RuleEngineStatus = iota
	// RuleEngineOff will not process any rule
	RuleEngineOff RuleEngineStatus = iota
)

// ParseRuleEngineStatus parses the rule engine status
func ParseRuleEngineStatus(re string) (RuleEngineStatus, error) {
	switch strings.ToLower(re) {
	case "on":
		return RuleEngineOn, nil
	case "detectiononly":
		return RuleEngineDetectionOnly, nil
	case "off":
		return RuleEngineOff, nil
	}
	return -1, fmt.Errorf("invalid rule engine status: %q", re)
}

// String returns the string representation of the
// rule engine status
func (re RuleEngineStatus) String() string {
	switch re {
	case RuleEngineOn:
		return "On"
	case RuleEngineDetectionOnly:
		return "DetectionOnly"
	case RuleEngineOff:
		return "Off"
	}
	return "unknown"
}

// BodyLimitAction represents the action to take when
// the body size exceeds the configured limit.
type BodyLimitAction int

const (
	// BodyLimitActionProcessPartial will process the body
	// up to the limit and then ignores the remaining body bytes
	BodyLimitActionProcessPartial BodyLimitAction = 0
	// BodyLimitActionReject will reject the connection in case
	// the body size exceeds the configured limit
	BodyLimitActionReject BodyLimitAction = 1
)

type AuditLogPart byte

const (
	// AuditLogPartRequestHeaders is the request headers part
	AuditLogPartRequestHeaders AuditLogPart = 'B'
	// AuditLogPartRequestBody is the request body part
	AuditLogPartRequestBody AuditLogPart = 'C'
	// AuditLogPartIntermediaryResponseHeaders is the intermediary response headers part
	AuditLogPartIntermediaryResponseHeaders AuditLogPart = 'D'
	// AuditLogPartIntermediaryResponseBody is the intermediary response body part
	AuditLogPartIntermediaryResponseBody AuditLogPart = 'E'
	// AuditLogPartResponseHeaders is the final response headers part
	AuditLogPartResponseHeaders AuditLogPart = 'F'
	// AuditLogPartResponseBody is the final response body part
	AuditLogPartResponseBody AuditLogPart = 'G'
	// AuditLogPartAuditLogTrailer is the audit log trailer part
	AuditLogPartAuditLogTrailer AuditLogPart = 'H'
	// AuditLogPartRequestBodyAlternative is the request body replaced part
	AuditLogPartRequestBodyAlternative AuditLogPart = 'I'
	// AuditLogPartUploadedFiles is the uploaded files part
	AuditLogPartUploadedFiles AuditLogPart = 'J'
	// AuditLogPartRulesMatched is the matched rules part
	AuditLogPartRulesMatched AuditLogPart = 'K'
)

// AuditLogParts represents the parts of the audit log
// A: Audit log header (mandatory).
// B: Request headers.
// C: Request body
// D: Reserved for intermediary response headers; not implemented yet.
// E: Intermediary response body (not implemented yet).
// F: Final response headers
// G: Reserved for the actual response body; not implemented yet.
// H: Audit log trailer.
// I: This part is a replacement for part C.
// J: This part contains information about the files uploaded using multipart/form-data encoding.
// K: This part contains a full list of every rule that matched (one per line)
// Z: Final boundary, signifies the end of the entry (mandatory).
type AuditLogParts []AuditLogPart

// orderedAuditLogParts defines the canonical order for audit log parts (BCDEFGHIJK)
var orderedAuditLogParts = []AuditLogPart{
	AuditLogPartRequestHeaders,              // B
	AuditLogPartRequestBody,                 // C
	AuditLogPartIntermediaryResponseHeaders, // D
	AuditLogPartIntermediaryResponseBody,    // E
	AuditLogPartResponseHeaders,             // F
	AuditLogPartResponseBody,                // G
	AuditLogPartAuditLogTrailer,             // H
	AuditLogPartRequestBodyAlternative,      // I
	AuditLogPartUploadedFiles,               // J
	AuditLogPartRulesMatched,                // K
}

// validOpts is generated from orderedAuditLogParts for efficient validation
var validOpts = func() map[AuditLogPart]struct{} {
	m := make(map[AuditLogPart]struct{}, len(orderedAuditLogParts))
	for _, part := range orderedAuditLogParts {
		m[part] = struct{}{}
	}
	return m
}()

// ParseAuditLogParts parses the audit log parts
func ParseAuditLogParts(opts string) (AuditLogParts, error) {
	if !strings.HasPrefix(opts, "A") {
		return nil, errors.New("audit log parts is required to start with A")
	}

	if !strings.HasSuffix(opts, "Z") {
		return nil, errors.New("audit log parts is required to end with Z")
	}

	parts := opts[1 : len(opts)-1]
	for _, p := range parts {
		if _, ok := validOpts[AuditLogPart(p)]; !ok {
			return AuditLogParts(""), fmt.Errorf("invalid audit log parts %q", opts)
		}
	}
	return AuditLogParts(parts), nil
}

// ApplyAuditLogParts applies audit log parts modifications to the base parts.
// It supports adding parts with '+' prefix (e.g., "+E") or removing parts with '-' prefix (e.g., "-E").
// For absolute values (e.g., "ABCDEFZ"), use ParseAuditLogParts instead.
// Parts 'A' and 'Z' are mandatory and cannot be added or removed.
func ApplyAuditLogParts(base AuditLogParts, modification string) (AuditLogParts, error) {
	if len(modification) == 0 {
		return nil, errors.New("modification string cannot be empty")
	}

	// Check if this is a modification (starts with + or -)
	if modification[0] != '+' && modification[0] != '-' {
		// This is an absolute value, parse it directly
		return ParseAuditLogParts(modification)
	}

	isAddition := modification[0] == '+'
	partsToModify := modification[1:]

	// Validate all parts to modify
	for _, p := range partsToModify {
		// Parts A and Z are mandatory and cannot be added or removed
		if p == 'A' || p == 'Z' {
			return nil, fmt.Errorf("audit log parts A and Z are mandatory and cannot be modified")
		}
		if _, ok := validOpts[AuditLogPart(p)]; !ok {
			return nil, fmt.Errorf("invalid audit log part %q", p)
		}
	}

	// Create a map of current parts for efficient lookup
	partsMap := make(map[AuditLogPart]struct{})
	for _, p := range base {
		partsMap[p] = struct{}{}
	}

	if isAddition {
		// Add new parts
		for _, p := range partsToModify {
			partsMap[AuditLogPart(p)] = struct{}{}
		}
	} else {
		// Remove parts
		for _, p := range partsToModify {
			delete(partsMap, AuditLogPart(p))
		}
	}

	// Convert map back to slice, maintaining the canonical order
	result := make([]AuditLogPart, 0, len(partsMap))
	for _, part := range orderedAuditLogParts {
		if _, ok := partsMap[part]; ok {
			result = append(result, part)
		}
	}

	return AuditLogParts(result), nil
}

// Interruption is used to notify the Coraza implementation
// that the transaction must be disrupted, for example:
//
//	if it := tx.Interruption; it != nil {
//		return show403()
//	}
type Interruption struct {
	// Rule that caused the interruption
	RuleID int

	// drop, deny, redirect
	Action string

	// Force this status code
	Status int

	// Parameters used by proxy and redirect
	Data string
}

// BodyBufferOptions is used to feed a coraza.BodyBuffer with parameters
type BodyBufferOptions struct {
	// TmpPath is the path to store temporary files
	TmpPath string
	// MemoryLimit is the maximum amount of memory to be stored in memory
	// Once the limit is reached, the file will be stored on disk
	MemoryLimit int64
	// Limit is the overall maximum amount of memory to be buffered
	Limit int64
}
