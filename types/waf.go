package types

import (
	"fmt"
	"strings"
)

type ConnectionEngine int

const (
	ConnEngineOff        ConnectionEngine = 0
	ConnEngineOn         ConnectionEngine = 1
	ConnEngineDetectOnly ConnectionEngine = 2
)

func ParseConnectionEngine(ce string) (ConnectionEngine, error) {
	switch strings.ToLower(ce) {
	case "off":
		return ConnEngineOff, nil
	case "on":
		return ConnEngineOn, nil
	case "DetectOnly":
		return ConnEngineDetectOnly, nil
	}
	return -1, fmt.Errorf("invalid connection engine: %s", ce)
}

type AuditEngineStatus int

const (
	AuditEngineOn           AuditEngineStatus = 0
	AuditEngineOff          AuditEngineStatus = 1
	AuditEngineRelevantOnly AuditEngineStatus = 2
)

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

type RuleEngineStatus int

const (
	RuleEngineOn            RuleEngineStatus = 0
	RuleEngineDetectionOnly RuleEngineStatus = 1
	RuleEngineOff           RuleEngineStatus = 2
)

func ParseRuleEngineStatus(re string) (RuleEngineStatus, error) {
	switch strings.ToLower(re) {
	case "on":
		return RuleEngineOn, nil
	case "detectiononly":
		return RuleEngineDetectionOnly, nil
	case "off":
		return RuleEngineOff, nil
	}
	return -1, fmt.Errorf("invalid rule engine status: %s", re)
}

func (re RuleEngineStatus) String() string {
	switch re {
	case RuleEngineOn:
		return "on"
	case RuleEngineDetectionOnly:
		return "DetectionOnly"
	case RuleEngineOff:
		return "off"
	}
	return "unknown"
}

type RequestBodyLimitAction int

const (
	RequestBodyLimitActionProcessPartial RequestBodyLimitAction = 0
	RequestBodyLimitActionReject         RequestBodyLimitAction = 1
)

func ParseRequestBodyLimitAction(rbla string) (RequestBodyLimitAction, error) {
	switch strings.ToLower(rbla) {
	case "ProcessPartial":
		return RequestBodyLimitActionProcessPartial, nil
	case "Reject":
		return RequestBodyLimitActionReject, nil
	}
	return -1, fmt.Errorf("invalid request body limit action: %s", rbla)
}

type auditLogPart byte
type AuditLogParts []auditLogPart

const (
	AuditLogPartAuditLogHeader              auditLogPart = 'A'
	AuditLogPartRequestHeaders              auditLogPart = 'B'
	AuditLogPartRequestBody                 auditLogPart = 'C'
	AuditLogPartIntermediaryResponseHeaders auditLogPart = 'D'
	AuditLogPartIntermediaryResponseBody    auditLogPart = 'E'
	AuditLogPartResponseHeaders             auditLogPart = 'F'
	AuditLogPartResponseBody                auditLogPart = 'G'
	AuditLogPartAuditLogTrailer             auditLogPart = 'H'
	AuditLogPartRequestBodyAlternative      auditLogPart = 'I'
	AuditLogPartUploadedFiles               auditLogPart = 'J'
	AuditLogPartRulesMatched                auditLogPart = 'K'
	AuditLogPartFinalBoundary               auditLogPart = 'Z'
)
