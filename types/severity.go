// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"fmt"
	"strconv"
	"strings"
)

// RuleSeverity represents the severity of a triggered rule
// It can have a numeric value or string value
// There are 8 levels of severity:
// 0 - Emergency
// 1 - Alert
// 2 - Critical
// 3 - Error
// 4 - Warning
// 5 - Notice
// 6 - Info
// 7 - Debug
// RuleSeverity is used by error callbacks to chose wether to
// log the error or not
type RuleSeverity int

const (
	// RuleSeverityEmergency represents the emergency severity
	// We "shold" exit the process immediately
	RuleSeverityEmergency RuleSeverity = 0
	// RuleSeverityAlert represents the alert severity
	RuleSeverityAlert RuleSeverity = 1
	// RuleSeverityCritical represents the critical severity
	RuleSeverityCritical RuleSeverity = 2
	// RuleSeverityError represents the error severity
	RuleSeverityError RuleSeverity = 3
	// RuleSeverityWarning represents the warning severity
	RuleSeverityWarning RuleSeverity = 4
	// RuleSeverityNotice represents the notice severity
	RuleSeverityNotice RuleSeverity = 5
	// RuleSeverityInfo represents the info severity
	RuleSeverityInfo RuleSeverity = 6
	// RuleSeverityDebug represents the debug severity
	RuleSeverityDebug RuleSeverity = 7
)

// String returns the string representation of the severity
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

// Int returns the integer value of the severity
func (rs RuleSeverity) Int() int {
	return int(rs)
}

// ParseRuleSeverity parses a string into a RuleSeverity
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
