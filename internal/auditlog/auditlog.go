// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Log represents the main struct for audit log data
type Log struct {
	// Parts contains the parts of the audit log
	Parts_ types.AuditLogParts `json:"-"`

	// Transaction contains the transaction information
	Transaction_ Transaction `json:"transaction"`

	// Messages contains the triggered rules information
	Messages_ []plugintypes.AuditLogMessage `json:"messages,omitempty"`
}

func (l *Log) Parts() types.AuditLogParts {
	return l.Parts_
}

func (l *Log) Transaction() plugintypes.AuditLogTransaction {
	return l.Transaction_
}

func (l *Log) Messages() []plugintypes.AuditLogMessage {
	return l.Messages_
}

// uLog allows to unmarshal the Log struct whose Messages field is
// slice of AuditLogMessage. This is needed because the json
// package cannot unmarshal interfaces but concrete types.
type uLog struct {
	Transaction_ Transaction `json:"transaction"`
	Messages_    []Message   `json:"messages"`
}

func (l *Log) UnmarshalJSON(data []byte) error {
	ul := uLog{}
	err := json.Unmarshal(data, &ul)
	if err != nil {
		return err
	}

	l.Transaction_ = ul.Transaction_
	if len(ul.Messages_) == 0 {
		return nil
	}

	l.Messages_ = make([]plugintypes.AuditLogMessage, len(ul.Messages_))
	for i, m := range ul.Messages_ {
		l.Messages_[i] = m
	}

	return nil
}

var _ plugintypes.AuditLog = (*Log)(nil)

// Transaction contains transaction specific
// information
type Transaction struct {
	// Timestamp "02/Jan/2006:15:04:20 -0700" format
	Timestamp_     string `json:"timestamp"`
	UnixTimestamp_ int64  `json:"unix_timestamp"`

	// Unique ID
	ID_ string `json:"id"`

	// Client IP Address string representation
	ClientIP_ string `json:"client_ip"`

	ClientPort_ int                  `json:"client_port"`
	HostIP_     string               `json:"host_ip"`
	HostPort_   int                  `json:"host_port"`
	ServerID_   string               `json:"server_id"`
	Request_    *TransactionRequest  `json:"request,omitempty"`
	Response_   *TransactionResponse `json:"response,omitempty"`
	Producer_   *TransactionProducer `json:"producer,omitempty"`
}

var _ plugintypes.AuditLogTransaction = Transaction{}

func (t Transaction) Timestamp() string {
	return t.Timestamp_
}

func (t Transaction) UnixTimestamp() int64 {
	return t.UnixTimestamp_
}

func (t Transaction) ID() string {
	return t.ID_
}

func (t Transaction) ClientIP() string {
	return t.ClientIP_
}

func (t Transaction) ClientPort() int {
	return t.ClientPort_
}

func (t Transaction) HostIP() string {
	return t.HostIP_
}

func (t Transaction) HostPort() int {
	return t.HostPort_
}

func (t Transaction) ServerID() string {
	return t.ServerID_
}

func (t Transaction) HasRequest() bool {
	return t.Request_ != nil
}

func (t Transaction) Request() plugintypes.AuditLogTransactionRequest {
	return t.Request_
}

func (t Transaction) HasResponse() bool {
	return t.Response_ != nil
}

func (t Transaction) Response() plugintypes.AuditLogTransactionResponse {
	return t.Response_
}

func (t Transaction) Producer() plugintypes.AuditLogTransactionProducer {
	return t.Producer_
}

// TransactionResponse contains response specific
// information
type TransactionResponse struct {
	Protocol_ string              `json:"protocol"`
	Status_   int                 `json:"status"`
	Headers_  map[string][]string `json:"headers"`
	Body_     string              `json:"body"`
}

var _ plugintypes.AuditLogTransactionResponse = (*TransactionResponse)(nil)

func (tRes *TransactionResponse) Protocol() string {
	if tRes == nil {
		return ""
	}

	return tRes.Protocol_
}

func (tr *TransactionResponse) Status() int {
	if tr == nil {
		return 0
	}

	return tr.Status_
}

func (tr *TransactionResponse) Headers() map[string][]string {
	if tr == nil {
		return nil
	}

	return tr.Headers_
}

func (tr *TransactionResponse) Body() string {
	if tr == nil {
		return ""
	}

	return tr.Body_
}

// TransactionProducer contains producer specific
// information for debugging
type TransactionProducer struct {
	Connector_  string   `json:"connector"`
	Version_    string   `json:"version"`
	Server_     string   `json:"server"`
	RuleEngine_ string   `json:"rule_engine"`
	Stopwatch_  string   `json:"stopwatch"`
	Rulesets_   []string `json:"rulesets"`
}

var _ plugintypes.AuditLogTransactionProducer = (*TransactionProducer)(nil)

func (tp *TransactionProducer) Connector() string {
	return tp.Connector_
}

func (tp *TransactionProducer) Version() string {
	return tp.Version_
}

func (tp *TransactionProducer) Server() string {
	return tp.Server_
}

func (tp *TransactionProducer) RuleEngine() string {
	return tp.RuleEngine_
}

func (tp *TransactionProducer) Stopwatch() string {
	return tp.Stopwatch_
}

func (tp *TransactionProducer) Rulesets() []string {
	return tp.Rulesets_
}

// TransactionRequest contains request specific
// information
type TransactionRequest struct {
	Method_      string                                        `json:"method"`
	Protocol_    string                                        `json:"protocol"`
	URI_         string                                        `json:"uri"`
	HTTPVersion_ string                                        `json:"http_version"`
	Headers_     map[string][]string                           `json:"headers"`
	Body_        string                                        `json:"body"`
	Files_       []plugintypes.AuditLogTransactionRequestFiles `json:"files"`
}

var _ plugintypes.AuditLogTransactionRequest = (*TransactionRequest)(nil)

func (tReq *TransactionRequest) Method() string {
	if tReq == nil {
		return ""
	}
	return tReq.Method_
}

func (tr *TransactionRequest) Protocol() string {
	if tr == nil {
		return ""
	}
	return tr.Protocol_
}

func (tr *TransactionRequest) URI() string {
	if tr == nil {
		return ""
	}
	return tr.URI_
}

func (tr *TransactionRequest) HTTPVersion() string {
	if tr == nil {
		return ""
	}
	return tr.HTTPVersion_
}

func (tr *TransactionRequest) Headers() map[string][]string {
	if tr == nil {
		return nil
	}

	return tr.Headers_
}

func (tr *TransactionRequest) Body() string {
	if tr == nil {
		return ""
	}

	return tr.Body_
}

func (tr *TransactionRequest) Files() []plugintypes.AuditLogTransactionRequestFiles {
	if tr == nil {
		return nil
	}

	return tr.Files_
}

// TransactionRequestFiles contains information
// for the uploaded files using multipart forms
type TransactionRequestFiles struct {
	Name_ string `json:"name"`
	Size_ int64  `json:"size"`
	Mime_ string `json:"mime"`
}

var _ plugintypes.AuditLogTransactionRequestFiles = (*TransactionRequestFiles)(nil)

func (trf TransactionRequestFiles) Name() string {
	return trf.Name_
}

func (trf TransactionRequestFiles) Size() int64 {
	return trf.Size_
}

func (trf TransactionRequestFiles) Mime() string {
	return trf.Mime_
}

// Message contains information about the triggered
// rules
type Message struct {
	Actionset_ string       `json:"actionset"`
	Message_   string       `json:"message"`
	Data_      *MessageData `json:"data"`
}

var _ plugintypes.AuditLogMessage = Message{}

func (m Message) Actionset() string {
	return m.Actionset_
}

func (m Message) Message() string {
	return m.Message_
}

func (m Message) Data() plugintypes.AuditLogMessageData {
	return m.Data_
}

// MessageData contains information about the triggered
// rules in detail
type MessageData struct {
	File_     string             `json:"file"`
	Line_     int                `json:"line"`
	ID_       int                `json:"id"`
	Rev_      string             `json:"rev"`
	Msg_      string             `json:"msg"`
	Data_     string             `json:"data"`
	Severity_ types.RuleSeverity `json:"severity"`
	Ver_      string             `json:"ver"`
	Maturity_ int                `json:"maturity"`
	Accuracy_ int                `json:"accuracy"`
	Tags_     []string           `json:"tags"`
	Raw_      string             `json:"raw"`
}

var _ plugintypes.AuditLogMessageData = (*MessageData)(nil)

func (md *MessageData) File() string {
	return md.File_
}

func (md *MessageData) Line() int {
	return md.Line_
}

func (md *MessageData) ID() int {
	return md.ID_
}

func (md *MessageData) Rev() string {
	return md.Rev_
}

func (md *MessageData) Msg() string {
	return md.Msg_
}

func (md *MessageData) Data() string {
	return md.Data_
}

func (md *MessageData) Severity() types.RuleSeverity {
	return md.Severity_
}

func (md *MessageData) Ver() string {
	return md.Ver_
}

func (md *MessageData) Maturity() int {
	return md.Maturity_
}

func (md *MessageData) Accuracy() int {
	return md.Accuracy_
}

func (md *MessageData) Tags() []string {
	return md.Tags_
}

func (md *MessageData) Raw() string {
	return md.Raw_
}
