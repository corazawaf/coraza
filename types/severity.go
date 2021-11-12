package types

import (
	"fmt"
	"strconv"
	"strings"
)

type RuleSeverity int

const (
	RuleSeverityEmergency RuleSeverity = 0
	RuleSeverityAlert     RuleSeverity = 1
	RuleSeverityCritical  RuleSeverity = 2
	RuleSeverityError     RuleSeverity = 3
	RuleSeverityWarning   RuleSeverity = 4
	RuleSeverityNotice    RuleSeverity = 5
	RuleSeverityInfo      RuleSeverity = 6
	RuleSeverityDebug     RuleSeverity = 7
)

func (rs RuleSeverity) String() string {
	switch rs {
	case RuleSeverityEmergency:
		return "emergency"
	case RuleSeverityAlert:
		return "alert"
	case RuleSeverityCritical:
		return "critical"
	case RuleSeverityError:
		return "error"
	case RuleSeverityWarning:
		return "warning"
	case RuleSeverityNotice:
		return "notice"
	case RuleSeverityInfo:
		return "info"
	case RuleSeverityDebug:
		return "debug"
	}
	return "unknown"
}

func (rs RuleSeverity) Int() int {
	return int(rs)
}

func ParseRuleSeverity(input string) (RuleSeverity, error) {
	if len(input) == 1 {
		s, err := strconv.Atoi(input)
		if err != nil {
			return RuleSeverity(0), err
		}
		if s < 0 || s > 7 {
			return RuleSeverity(0), fmt.Errorf("invalid severity: %d", s)
		}
		return RuleSeverity(s), nil
	}
	switch strings.ToLower(input) {
	case "emergency":
		return RuleSeverityEmergency, nil
	case "alert":
		return RuleSeverityAlert, nil
	case "critical":
		return RuleSeverityCritical, nil
	case "error":
		return RuleSeverityError, nil
	case "warning":
		return RuleSeverityWarning, nil
	case "notice":
		return RuleSeverityNotice, nil
	case "info":
		return RuleSeverityInfo, nil
	case "debug":
		return RuleSeverityDebug, nil
	}
	return 0, fmt.Errorf("Unknown severity: %s", input)
}
