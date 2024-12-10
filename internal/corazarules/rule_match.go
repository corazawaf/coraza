// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazarules

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	experimentalTypes "github.com/corazawaf/coraza/v3/experimental/types"
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
	// Metadata of the matched data
	Metadata_ *experimentalTypes.DataMetadataList
}

var _ types.MatchData = (*MatchData)(nil)

var _ experimentalTypes.MatchData = (*MatchData)(nil)

var _ experimentalTypes.MatchData = (*MatchData)(nil)

func (m MatchData) Variable() variables.RuleVariable {
	return m.Variable_
}

func (m MatchData) Key() string {
	return m.Key_
}

func (m MatchData) Value() string {
	return m.Value_
}

func (m MatchData) Message() string {
	return m.Message_
}

func (m MatchData) Data() string {
	return m.Data_
}

func (m MatchData) ChainLevel() int {
	return m.ChainLevel_
}

func (m *MatchData) DataMetadata(allowedMetadatas []experimentalTypes.DataMetadata) experimentalTypes.DataMetadataList {
	// Evaluate the metadata if it's not set
	if m.Metadata_ == nil {
		m.Metadata_ = &experimentalTypes.DataMetadataList{}
	}
	m.Metadata_.EvaluateMetadata(m.Value_, allowedMetadatas)
	return *m.Metadata_
}

// ActionName is used to identify an action.
type DisruptiveAction int

const (
	DisruptiveActionUnknown DisruptiveAction = iota
	DisruptiveActionAllow
	DisruptiveActionDeny
	DisruptiveActionDrop
	DisruptiveActionPass
	DisruptiveActionRedirect
)

var DisruptiveActionMap = map[string]DisruptiveAction{
	"allow":    DisruptiveActionAllow,
	"deny":     DisruptiveActionDeny,
	"drop":     DisruptiveActionDrop,
	"pass":     DisruptiveActionPass,
	"redirect": DisruptiveActionRedirect,
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
	// Name of the disruptive action
	// Note: not exposed in coraza v3.0.*
	DisruptiveAction_ DisruptiveAction
	// Is meant to be logged
	Log_ bool
	// Server IP address
	ServerIPAddress_ string
	// Client IP address
	ClientIPAddress_ string
	// A slice of matched variables
	MatchedDatas_ []experimentalTypes.MatchData

	Rule_ types.RuleMetadata

	Context_ context.Context
}

var _ types.MatchedRule = (*MatchedRule)(nil)

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

func (mr *MatchedRule) Log() bool {
	return mr.Log_
}

func (mr *MatchedRule) ServerIPAddress() string {
	return mr.ServerIPAddress_
}

func (mr *MatchedRule) ClientIPAddress() string {
	return mr.ClientIPAddress_
}

func (mr *MatchedRule) MatchedDatas() []types.MatchData {
	var matchedDatas []types.MatchData
	for _, md := range mr.MatchedDatas_ {
		matchedDatas = append(matchedDatas, md)
	}
	return matchedDatas
}

func (mr *MatchedRule) MatchedDatasExperimental_() []experimentalTypes.MatchData {
	return mr.MatchedDatas_
}

func (mr *MatchedRule) Rule() types.RuleMetadata {
	return mr.Rule_
}

// Context returns the context associated with the transaction
// This is useful for logging purposes where you want to add
// additional information to the log.
// The context can be easily retrieved in the logger using
// an ancillary interface:
// ```
//
//	 type Contexter interface {
//			Context() context.Context
//		}
//
// ```
// and then using it like this:
//
// ```
//
//	func errorLogCb(mr types.MatchedRule) {
//	     ctx := context.Background()
//		 if ctxer, ok := mr.(Contexter); ok {
//	    	ctx = ctxer.Context()
//		 }
//	     logger.Context(ctx).Error().Msg("...")
//	}
//
// ```
func (mr *MatchedRule) Context() context.Context {
	return mr.Context_
}

const maxSizeLogMessage = 280

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
			writeDisruptiveActionSpecificLog(log, mr)
		} else {
			log.WriteString("Coraza: Warning. ")
		}
		mr.matchData(log, matchData)
		mr.writeDetails(log, matchData)
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
		writeDisruptiveActionSpecificLog(log, mr)
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

	return log.String()
}

func writeDisruptiveActionSpecificLog(log *strings.Builder, mr MatchedRule) {
	switch mr.DisruptiveAction_ {
	case DisruptiveActionAllow:
		fmt.Fprintf(log, "Coraza: Access allowed (phase %d). ", mr.Rule_.Phase())
	case DisruptiveActionDeny:
		fmt.Fprintf(log, "Coraza: Access denied (phase %d). ", mr.Rule_.Phase())
	case DisruptiveActionDrop:
		fmt.Fprintf(log, "Coraza: Access dropped (phase %d). ", mr.Rule_.Phase())
	case DisruptiveActionPass:
		log.WriteString("Coraza: Warning. ")
	case DisruptiveActionRedirect:
		fmt.Fprintf(log, "Coraza: Access redirected (phase %d). ", mr.Rule_.Phase())
	default:
		fmt.Fprintf(log, "Coraza: Custom disruptive action triggered (phase %d). ", mr.Rule_.Phase())
	}
}
