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

package coraza

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

// MatchData works like VariableKey but is used for logging
// so it contains the collection as a string and it's value
type MatchData struct {
	// variable name stored for cache
	VariableName string
	// Variable
	Variable variables.RuleVariable
	// Key of the variable, blank if no key is required
	Key string
	// Value of the current VARIABLE:KEY
	Value string
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
	ServerIpAddress string
	// Client IP address
	ClientIpAddress string
	// A slice of matched variables
	MatchedData MatchData
	// A reference to the triggered rule
	Rule Rule
}

func (mr MatchedRule) details() string {
	log := &strings.Builder{}
	msg := mr.Message
	data := mr.Data
	if len(data) > 200 {
		msg = data[:200]
	}
	resolvedIp := ""
	log.WriteString(fmt.Sprintf(" [file %q] [line %q] [id %q] [rev %q] [msg %q] [data %q] [severity %q] [ver %q] [maturity %q] [accuracy %q]",
		mr.Rule.File, strconv.Itoa(mr.Rule.Line), strconv.Itoa(mr.Rule.ID), mr.Rule.Rev, msg, data, mr.Rule.Severity.String(), mr.Rule.Version,
		strconv.Itoa(mr.Rule.Maturity), strconv.Itoa(mr.Rule.Accuracy)))
	for _, t := range mr.Rule.Tags {
		log.WriteString(fmt.Sprintf(" [tag %q]", t))
	}
	log.WriteString(fmt.Sprintf(" [hostname %q] [uri %q] [unique_id %q]",
		resolvedIp, mr.URI, mr.ID))
	return log.String()
}

func (mr MatchedRule) matchData() string {
	v := mr.MatchedData.Variable.Name()
	if mr.MatchedData.Key != "" {
		v += fmt.Sprintf(":%s", mr.MatchedData.Key)
	}
	value := mr.MatchedData.Value
	if len(value) > 200 {
		value = value[:200]
	}
	log := &strings.Builder{}
	if mr.Rule.operator != nil {
		log.WriteString(fmt.Sprintf("Matched \"Operator %s matched %s at %s.",
			"", value, v))
	} else {
		log.WriteString("Matched.\"")
	}

	return ""
}

func (mr MatchedRule) AuditLog(code int) string {
	log := &strings.Builder{}
	log.WriteString(fmt.Sprintf("[client %q] ", mr.ClientIpAddress))
	if mr.Disruptive {
		log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule.Phase))
	} else {
		log.WriteString("Coraza: Warning. ")
	}
	log.WriteString(mr.matchData())
	log.WriteString(mr.details())
	return log.String()
}

// ErrorLog returns the same as audit log but without matchData
func (mr MatchedRule) ErrorLog(code int) string {
	msg := mr.Message
	if len(msg) > 200 {
		msg = msg[:200]
	}
	log := &strings.Builder{}
	log.WriteString(fmt.Sprintf("[client %q]", mr.ClientIpAddress))
	if mr.Disruptive {
		log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule.Phase))
	} else {
		log.WriteString("Coraza: Warning. ")
	}
	// log.WriteString(mr.matchData())
	log.WriteString(msg)
	log.WriteString(mr.details())
	return log.String()
}
