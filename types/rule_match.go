// Copyright 2022 Juan Pablo Tosso
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

	"github.com/corazawaf/coraza/v3/types/variables"
)

type RuleMetadata struct {
	ID       int
	File     string
	Line     int
	Rev      string
	Severity RuleSeverity
	Version  string
	Tags     []string
	Maturity int
	Accuracy int
	Operator string
	Phase    RulePhase
	Raw      string
	SecMark  string
}

// MatchData works like VariableKey but is used for logging,
// so it contains the collection as a string, and it's value
type MatchData struct {
	// variable name stored for cache
	VariableName string
	// Variable
	Variable variables.RuleVariable
	// Key of the variable, blank if no key is required
	Key string
	// Value of the current VARIABLE:KEY
	Value string
	// Macro expanded message
	Message string
	// Macro expanded logdata
	Data string
}

// // isNil is used to check whether the MatchData is empty
func (m MatchData) IsNil() bool {
	return m == MatchData{}
}

// MatchedRule contains a list of macro expanded messages,
// matched variables and a pointer to the rule
type MatchedRule struct {
	// Macro expanded message
	Message string
	// Macro expanded logdata
	Data string
	// Full request uri unparsed
	URI string
	// Transaction id
	ID string
	// Is disruptive
	Disruptive bool
	// Server IP address
	ServerIPAddress string
	// Client IP address
	ClientIPAddress string
	// A slice of matched variables
	MatchedDatas []MatchData

	Rule RuleMetadata
}

func (mr MatchedRule) details(matchData MatchData) string {
	log := &strings.Builder{}

	resolvedIP := ""
	msg := matchData.Message
	data := matchData.Data
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if len(data) > 200 {
		data = data[:200]
	}
	log.WriteString(fmt.Sprintf("[file %q] [line %q] [id %q] [rev %q] [msg %q] [data %q] [severity %q] [ver %q] [maturity %q] [accuracy %q]",
		mr.Rule.File, strconv.Itoa(mr.Rule.Line), strconv.Itoa(mr.Rule.ID), mr.Rule.Rev, msg, data, mr.Rule.Severity.String(), mr.Rule.Version,
		strconv.Itoa(mr.Rule.Maturity), strconv.Itoa(mr.Rule.Accuracy)))
	for _, t := range mr.Rule.Tags {
		log.WriteString(fmt.Sprintf(" [tag %q]", t))
	}
	log.WriteString(fmt.Sprintf(" [hostname %q] [uri %q] [unique_id %q]",
		resolvedIP, mr.URI, mr.ID))
	return log.String()
}

func (mr MatchedRule) matchData(matchData MatchData) string {
	log := &strings.Builder{}
	for _, matchData := range mr.MatchedDatas {
		v := matchData.Variable.Name()
		if matchData.Key != "" {
			v += fmt.Sprintf(":%s", matchData.Key)
		}
		value := matchData.Value
		if len(value) > 200 {
			value = value[:200]
		}
		if mr.Rule.Operator != "" {
			log.WriteString(fmt.Sprintf("Matched \"Operator %s matched %s at %s.",
				"", value, v))
		} else {
			log.WriteString("Matched.\"")
		}
	}
	return log.String()
}

// AuditLog transforms the matched rule into an error log
// using the legacy Modsecurity syntax
func (mr MatchedRule) AuditLog(code int) string {
	log := &strings.Builder{}
	for _, matchData := range mr.MatchedDatas {
		log.WriteString(fmt.Sprintf("[client %q] ", mr.ClientIPAddress))
		if mr.Disruptive {
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule.Phase))
		} else {
			log.WriteString("Coraza: Warning. ")
		}
		log.WriteString(mr.matchData(matchData))
		log.WriteString(mr.details(matchData))
		log.WriteString("\n")
	}
	return log.String()
}

// ErrorLog returns the same as audit log but without matchData
func (mr MatchedRule) ErrorLog(code int) string {
	msg := mr.MatchedDatas[0].Message
	for _, md := range mr.MatchedDatas {
		// Use 1st set message of rule chain as message
		if md.Message != "" {
			msg = md.Message
			break
		}
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}

	log := &strings.Builder{}

	for _, matchData := range mr.MatchedDatas {
		log.WriteString(fmt.Sprintf("[client %q] ", mr.ClientIPAddress))
		if mr.Disruptive {
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule.Phase))
		} else {
			log.WriteString("Coraza: Warning. ")
		}
		log.WriteString(msg)
		log.WriteString(" ")
		log.WriteString(mr.details(matchData))
		log.WriteString("\n")
	}
	return log.String()
}
