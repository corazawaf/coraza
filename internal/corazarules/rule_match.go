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
	// Keeps track of the chain depth in which the data matched.
	// Multiphase specific field
	ChainLevel_ int
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

func (m *MatchData) ChainLevel() int {
	return m.ChainLevel_
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

const maxSizeLogMessage = 200

func (mr MatchedRule) writeDetails(log *strings.Builder, matchData types.MatchData) {
	msg := matchData.Message()
	data := matchData.Data()
	if len(msg) > maxSizeLogMessage {
		msg = msg[:maxSizeLogMessage]
	}
	if len(data) > maxSizeLogMessage {
		data = data[:maxSizeLogMessage]
	}
	fmt.Fprintf(log, "[file %q] [line %q] [id %q] [rev %q] [msg %q] [data %q] [severity %q] [ver %q] [maturity %q] [accuracy %q]",
		mr.Rule_.File(), strconv.Itoa(mr.Rule_.Line()), strconv.Itoa(mr.Rule_.ID()), mr.Rule_.Revision(), msg, data, mr.Rule_.Severity().String(), mr.Rule_.Version(),
		strconv.Itoa(mr.Rule_.Maturity()), strconv.Itoa(mr.Rule_.Accuracy()))
	for _, t := range mr.Rule_.Tags() {
		fmt.Fprintf(log, " [tag %q]", t)
	}
	fmt.Fprintf(log, " [hostname %q] [uri %q] [unique_id %q]", mr.ServerIPAddress_, mr.URI_, mr.TransactionID_)
}

func (mr MatchedRule) writeExtraRuleDetails(log *strings.Builder, matchData types.MatchData, n int) {
	msg := matchData.Message()
	data := matchData.Data()
	if len(msg) > maxSizeLogMessage {
		msg = msg[:maxSizeLogMessage]
	}
	if len(data) > maxSizeLogMessage {
		data = data[:maxSizeLogMessage]
	}
	fmt.Fprintf(log, "[msg_match_%d %q] [data_match_%d %q]", n, msg, n, data)
}

func (mr MatchedRule) matchData(log *strings.Builder, matchData types.MatchData) {
	value := matchData.Value()
	if len(value) > maxSizeLogMessage {
		value = value[:maxSizeLogMessage]
	}
	op := mr.Rule_.Operator()
	if op == "" {
		log.WriteString("Matched.")
		return
	}
	log.WriteString("Matched Operator ")
	log.WriteString(op)
	log.WriteString(" matched ")
	log.WriteString(value)
	log.WriteString(" at ")
	log.WriteString(matchData.Variable().Name())
	if matchData.Key() != "" {
		log.WriteString(":")
		log.WriteString(matchData.Key())
	}
	log.WriteString(".")
}

// AuditLog transforms the matched rule into an error log
// using the legacy Modsecurity syntax
func (mr MatchedRule) AuditLog() string {
	log := &strings.Builder{}
	for _, matchData := range mr.MatchedDatas_ {
		fmt.Fprintf(log, "[client %q] ", mr.ClientIPAddress_)
		if mr.Disruptive_ {
			fmt.Fprintf(log, "Coraza: Access denied (phase %d). ", mr.Rule_.Phase())
		} else {
			log.WriteString("Coraza: Warning. ")
		}
		mr.matchData(log, matchData)
		mr.writeDetails(log, matchData)
		log.WriteString("\n")
	}
	return log.String()
}

// ErrorLog returns the same as audit log but without matchData
func (mr MatchedRule) ErrorLog() string {
	matchData := mr.MatchedDatas_[0]
	msg := matchData.Message()
	for _, md := range mr.MatchedDatas_ {
		// Use 1st set message of rule chain as message
		if md.Message() != "" {
			msg = md.Message()
			break
		}
	}
	if len(msg) > maxSizeLogMessage {
		msg = msg[:maxSizeLogMessage]
	}

	log := &strings.Builder{}

	fmt.Fprintf(log, "[client %q] ", mr.ClientIPAddress_)
	if mr.Disruptive_ {
		fmt.Fprintf(log, "Coraza: Access denied (phase %d). ", mr.Rule_.Phase())
	} else {
		log.WriteString("Coraza: Warning. ")
	}
	log.WriteString(msg)
	log.WriteString(" ")
	mr.writeDetails(log, matchData)

	for n, matchData := range mr.MatchedDatas_ {
		if n == 0 {
			// Skipping first matchData, it has been just added to the log
			continue
		}
		if matchData.Message() != "" || matchData.Data() != "" {
			mr.writeExtraRuleDetails(log, matchData, n)
		}
	}

	log.WriteString("\n")
	return log.String()
}
