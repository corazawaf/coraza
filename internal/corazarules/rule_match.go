<<<<<<< Updated upstream
package corazawaf

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/types/variables"
	"strconv"
	"strings"
=======
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazarules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
>>>>>>> Stashed changes
)

// MatchData works like VariableKey but is used for logging,
// so it contains the collection as a string, and it's value
type MatchData struct {
	// variable name stored for cache
	VariableName_ string
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

func (m *MatchData) VariableName() string {
	return m.VariableName_
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

// IsNil is used to check whether the MatchData is empty
func (m MatchData) IsNil() bool {
	return m == MatchData{}
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
	ID_ string
	// Is disruptive
	Disruptive_ bool
	// Server IP address
	ServerIPAddress_ string
	// Client IP address
	ClientIPAddress_ string
	// A slice of matched variables
<<<<<<< Updated upstream
	MatchedDatas_ []MatchData

	Rule_ RuleMetadata
}

func (mr MatchedRule) details(matchData MatchData) string {
	log := &strings.Builder{}

	resolvedIP := ""
	msg := matchData.Message_
	data := matchData.Data_
=======
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

func (mr *MatchedRule) ID() string {
	return mr.ID_
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

func (mr MatchedRule) details(matchData types.MatchData) string {
	log := &strings.Builder{}

	resolvedIP := ""
	msg := matchData.Message()
	data := matchData.Data()
>>>>>>> Stashed changes
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if len(data) > 200 {
		data = data[:200]
	}
	log.WriteString(fmt.Sprintf("[file %q] [line %q] [id %q] [rev %q] [msg %q] [data %q] [severity %q] [ver %q] [maturity %q] [accuracy %q]",
<<<<<<< Updated upstream
		mr.Rule_.File_, strconv.Itoa(mr.Rule_.Line_), strconv.Itoa(mr.Rule_.ID_), mr.Rule_.Rev_, msg, data, mr.Rule_.Severity_.String(), mr.Rule_.Version_,
		strconv.Itoa(mr.Rule_.Maturity_), strconv.Itoa(mr.Rule_.Accuracy_)))
	for _, t := range mr.Rule_.Tags_ {
=======
		mr.Rule_.File(), strconv.Itoa(mr.Rule_.Line()), strconv.Itoa(mr.Rule_.ID()), mr.Rule_.Revision(), msg, data, mr.Rule_.Severity().String(), mr.Rule_.Version(),
		strconv.Itoa(mr.Rule_.Maturity()), strconv.Itoa(mr.Rule_.Accuracy())))
	for _, t := range mr.Rule_.Tags() {
>>>>>>> Stashed changes
		log.WriteString(fmt.Sprintf(" [tag %q]", t))
	}
	log.WriteString(fmt.Sprintf(" [hostname %q] [uri %q] [unique_id %q]",
		resolvedIP, mr.URI_, mr.ID_))
	return log.String()
}

<<<<<<< Updated upstream
func (mr MatchedRule) matchData(matchData MatchData) string {
	log := &strings.Builder{}
	for _, matchData := range mr.MatchedDatas_ {
		v := matchData.Variable_.Name()
		if matchData.Key_ != "" {
			v += fmt.Sprintf(":%s", matchData.Key_)
		}
		value := matchData.Value_
		if len(value) > 200 {
			value = value[:200]
		}
		if mr.Rule_.Operator_ != "" {
=======
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
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule_.Phase_))
=======
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule_.Phase()))
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
	msg := mr.MatchedDatas_[0].Message_
	for _, md := range mr.MatchedDatas_ {
		// Use 1st set message of rule chain as message
		if md.Message_ != "" {
			msg = md.Message_
=======
	msg := mr.MatchedDatas_[0].Message()
	for _, md := range mr.MatchedDatas_ {
		// Use 1st set message of rule chain as message
		if md.Message() != "" {
			msg = md.Message()
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule_.Phase_))
=======
			log.WriteString(fmt.Sprintf("Coraza: Access denied with code %d (phase %d). ", code, mr.Rule_.Phase()))
>>>>>>> Stashed changes
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
