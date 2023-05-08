// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazarules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// MatchData works like VariableKey but is used for logging,
// so it contains the collection as a string, and it's value
type MatchData struct {
	// Variable
	Variable_ variables.RuleVariable
	// Key of the variable, blank if no key is required
	Key_ string
	// Value of the current VARIABLE:KEY
	Value_ string
	// Macro expanded message
	Message_ string
	// Macro expanded logdata
	Data_ string
}

func (m *MatchData) Variable() variables.RuleVariable {
	return m.Variable_
}

func (m *MatchData) Key() string {
	return m.Key_
}

func (m *MatchData) Value() string {
	return m.Value_
}

func (m *MatchData) Message() string {
	return m.Message_
}

func (m *MatchData) Data() string {
	return m.Data_
}

// MatchedRule contains a list of macro expanded messages,
// matched variables and a pointer to the rule
type MatchedRule struct {
	// Macro expanded message
	Message_ string
	// Macro expanded logdata
	Data_ string
	// Full request uri unparsed
	URI_ string
	// Transaction id
	TransactionID_ string
	// Is disruptive
	Disruptive_ bool
	// Server IP address
	ServerIPAddress_ string
	// Client IP address
	ClientIPAddress_ string
	// A slice of matched variables
	MatchedDatas_ []types.MatchData

	Rule_ types.RuleMetadata
}

func (mr *MatchedRule) Message() string {
	return mr.Message_
}

func (mr *MatchedRule) Data() string {
	return mr.Data_
}

func (mr *MatchedRule) URI() string {
	return mr.URI_
}

func (mr *MatchedRule) TransactionID() string {
	return mr.TransactionID_
}

func (mr *MatchedRule) Disruptive() bool {
	return mr.Disruptive_
}

func (mr *MatchedRule) ServerIPAddress() string {
	return mr.ServerIPAddress_
}

func (mr *MatchedRule) ClientIPAddress() string {
	return mr.ClientIPAddress_
}

func (mr *MatchedRule) MatchedDatas() []types.MatchData {
	return mr.MatchedDatas_
}

func (mr *MatchedRule) Rule() types.RuleMetadata {
	return mr.Rule_
}

func (mr MatchedRule) writeDetails(log *strings.Builder, matchData types.MatchData) {
	msg := matchData.Message()
	data := matchData.Data()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if len(data) > 200 {
		data = data[:200]
	}
	log.WriteString(fmt.Sprintf("[file %q] [line %q] [id %q] [rev %q] [msg %q] [data %q] [severity %q] [ver %q] [maturity %q] [accuracy %q]",
		mr.Rule_.File(), strconv.Itoa(mr.Rule_.Line()), strconv.Itoa(mr.Rule_.ID()), mr.Rule_.Revision(), msg, data, mr.Rule_.Severity().String(), mr.Rule_.Version(),
		strconv.Itoa(mr.Rule_.Maturity()), strconv.Itoa(mr.Rule_.Accuracy())))
	for _, t := range mr.Rule_.Tags() {
		log.WriteString(fmt.Sprintf(" [tag %q]", t))
	}
	log.WriteString(fmt.Sprintf(" [hostname %q] [uri %q] [unique_id %q]",
		mr.ServerIPAddress_, mr.URI_, mr.TransactionID_))
}

func (mr MatchedRule) matchData(matchData types.MatchData) string {
	log := &strings.Builder{}
	for _, matchData := range mr.MatchedDatas_ {
		v := matchData.Variable().Name()
		if matchData.Key() != "" {
			v += fmt.Sprintf(":%s", matchData.Key())
		}
		value := matchData.Value()
		if len(value) > 200 {
			value = value[:200]
		}
		if mr.Rule_.Operator() != "" {
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
	for _, matchData := range mr.MatchedDatas_ {
		log.WriteString(fmt.Sprintf("[client %q] ", mr.ClientIPAddress_))
		if mr.Disruptive_ {
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule_.Phase()))
		} else {
			log.WriteString("Coraza: Warning. ")
		}
		log.WriteString(mr.matchData(matchData))
		mr.writeDetails(log, matchData)
		log.WriteString("\n")
	}
	return log.String()
}

// ErrorLog returns the same as audit log but without matchData
func (mr MatchedRule) ErrorLog(code int) string {
	msg := mr.MatchedDatas_[0].Message()
	for _, md := range mr.MatchedDatas_ {
		// Use 1st set message of rule chain as message
		if md.Message() != "" {
			msg = md.Message()
			break
		}
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}

	log := &strings.Builder{}

	for _, matchData := range mr.MatchedDatas_ {
		log.WriteString(fmt.Sprintf("[client %q] ", mr.ClientIPAddress_))
		if mr.Disruptive_ {
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule_.Phase()))
		} else {
			log.WriteString("Coraza: Warning. ")
		}
		log.WriteString(msg)
		log.WriteString(" ")
		mr.writeDetails(log, matchData)
		log.WriteString("\n")
	}
	return log.String()
}
