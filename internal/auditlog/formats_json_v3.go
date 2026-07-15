// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

const libmodsecurityJSONProducerName = "Coraza"

type libmodsecurityJSONFormatter struct{}

type libmodsecurityJSONLog struct {
	Transaction libmodsecurityJSONTransaction `json:"transaction"`
}

type libmodsecurityJSONTransaction struct {
	ClientIP      string                       `json:"client_ip"`
	Timestamp     string                       `json:"time_stamp"`
	ServerID      string                       `json:"server_id"`
	ClientPort    int                          `json:"client_port"`
	HostIP        string                       `json:"host_ip"`
	HostPort      int                          `json:"host_port"`
	UniqueID      string                       `json:"unique_id"`
	IsInterrupted bool                         `json:"is_interrupted"`
	Request       libmodsecurityJSONRequest    `json:"request"`
	Response      libmodsecurityJSONResponse   `json:"response"`
	Producer      *libmodsecurityJSONProducer  `json:"producer,omitempty"`
	Messages      *[]libmodsecurityJSONMessage `json:"messages,omitempty"`
}

type libmodsecurityJSONRequest struct {
	Method      string             `json:"method"`
	HTTPVersion string             `json:"http_version"`
	Hostname    string             `json:"hostname"`
	URI         string             `json:"uri"`
	Body        *string            `json:"body,omitempty"`
	Headers     *map[string]string `json:"headers,omitempty"`
}

type libmodsecurityJSONResponse struct {
	Body     *string            `json:"body,omitempty"`
	HTTPCode int                `json:"http_code"`
	Headers  *map[string]string `json:"headers,omitempty"`
}

type libmodsecurityJSONProducer struct {
	ModSecurity    string   `json:"modsecurity"`
	Connector      string   `json:"connector"`
	SecRulesEngine string   `json:"secrules_engine"`
	Components     []string `json:"components"`
}

type libmodsecurityJSONMessage struct {
	Message string                          `json:"message"`
	Details libmodsecurityJSONMessageDetail `json:"details"`
}

type libmodsecurityJSONMessageDetail struct {
	Match      string   `json:"match"`
	Reference  string   `json:"reference"`
	RuleID     string   `json:"ruleId"`
	File       string   `json:"file"`
	LineNumber string   `json:"lineNumber"`
	Data       string   `json:"data"`
	Severity   string   `json:"severity"`
	Ver        string   `json:"ver"`
	Rev        string   `json:"rev"`
	Tags       []string `json:"tags"`
	Maturity   string   `json:"maturity"`
	Accuracy   string   `json:"accuracy"`
}

type libmodsecurityJSONMessageData interface {
	Match() string
	Reference() string
}

func (libmodsecurityJSONFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	transaction := al.Transaction()
	formatted := libmodsecurityJSONLog{
		Transaction: libmodsecurityJSONTransaction{
			ClientIP:      transaction.ClientIP(),
			Timestamp:     libmodsecurityJSONTimestamp(transaction),
			ServerID:      transaction.ServerID(),
			ClientPort:    transaction.ClientPort(),
			HostIP:        transaction.HostIP(),
			HostPort:      transaction.HostPort(),
			UniqueID:      transaction.ID(),
			IsInterrupted: transaction.IsInterrupted(),
			Request: libmodsecurityJSONRequest{
				Method:   "-",
				Hostname: transaction.ServerID(),
			},
		},
	}

	if transaction.HasRequest() {
		request := transaction.Request()
		formatted.Transaction.Request.Method = dashIfEmpty(request.Method())
		formatted.Transaction.Request.HTTPVersion = libmodsecurityJSONHTTPVersion(request)
		formatted.Transaction.Request.URI = request.URI()

		if slices.Contains(al.Parts(), types.AuditLogPartRequestBody) {
			body := request.Body()
			formatted.Transaction.Request.Body = &body
		}

		if slices.Contains(al.Parts(), types.AuditLogPartRequestHeaders) {
			headers := libmodsecurityJSONHeaders(request.Headers())
			formatted.Transaction.Request.Headers = &headers
			if formatted.Transaction.Request.Hostname == "" {
				formatted.Transaction.Request.Hostname = libmodsecurityJSONHeader(headers, "host")
			}
		}
	}

	if transaction.HasResponse() {
		response := transaction.Response()
		formatted.Transaction.Response.HTTPCode = response.Status()

		if slices.Contains(al.Parts(), types.AuditLogPartIntermediaryResponseBody) {
			body := response.Body()
			formatted.Transaction.Response.Body = &body
		}

		if slices.Contains(al.Parts(), types.AuditLogPartResponseHeaders) {
			headers := libmodsecurityJSONHeaders(response.Headers())
			formatted.Transaction.Response.Headers = &headers
		}
	}

	if slices.Contains(al.Parts(), types.AuditLogPartAuditLogTrailer) {
		formatted.Transaction.Producer = libmodsecurityJSONProducerFrom(transaction.Producer())
		messages := libmodsecurityJSONMessages(al.Messages())
		formatted.Transaction.Messages = &messages
	}

	return json.Marshal(formatted)
}

func (libmodsecurityJSONFormatter) MIME() string {
	return "application/json; charset=utf-8"
}

func libmodsecurityJSONTimestamp(transaction plugintypes.AuditLogTransaction) string {
	if timestamp := transaction.UnixTimestamp(); timestamp != 0 {
		return time.Unix(0, timestamp).Format(time.ANSIC)
	}

	return transaction.Timestamp()
}

func libmodsecurityJSONHTTPVersion(request plugintypes.AuditLogTransactionRequest) string {
	version := request.HTTPVersion()
	if version == "" {
		version = request.Protocol()
	}

	if len(version) >= len("HTTP/") && strings.EqualFold(version[:len("HTTP/")], "HTTP/") {
		return version[len("HTTP/"):]
	}

	return version
}

func libmodsecurityJSONHeaders(headers map[string][]string) map[string]string {
	formatted := make(map[string]string, len(headers))
	for key, values := range headers {
		formatted[key] = strings.Join(values, ", ")
	}

	return formatted
}

func libmodsecurityJSONHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}

	return ""
}

func libmodsecurityJSONProducerFrom(producer plugintypes.AuditLogTransactionProducer) *libmodsecurityJSONProducer {
	formatted := &libmodsecurityJSONProducer{
		ModSecurity: libmodsecurityJSONProducerName,
		Components:  []string{},
	}
	if producer == nil {
		return formatted
	}

	formatted.Connector = strings.TrimSpace(strings.Join([]string{producer.Connector(), producer.Version()}, " "))
	formatted.SecRulesEngine = libmodsecurityJSONRuleEngine(producer.RuleEngine())
	formatted.Components = append(formatted.Components, producer.Rulesets()...)
	return formatted
}

func libmodsecurityJSONRuleEngine(ruleEngine string) string {
	switch strings.ToLower(ruleEngine) {
	case "on":
		return "Enabled"
	case "off":
		return "Disabled"
	default:
		return ruleEngine
	}
}

func libmodsecurityJSONMessages(messages []plugintypes.AuditLogMessage) []libmodsecurityJSONMessage {
	formatted := make([]libmodsecurityJSONMessage, 0, len(messages))
	for _, message := range messages {
		data := message.Data()
		if data == nil {
			continue
		}

		details := libmodsecurityJSONMessageDetail{
			RuleID:     strconv.Itoa(data.ID()),
			File:       data.File(),
			LineNumber: strconv.Itoa(data.Line()),
			Data:       data.Data(),
			Severity:   strconv.Itoa(data.Severity().Int()),
			Ver:        data.Ver(),
			Rev:        data.Rev(),
			Tags:       append([]string{}, data.Tags()...),
			Maturity:   strconv.Itoa(data.Maturity()),
			Accuracy:   strconv.Itoa(data.Accuracy()),
		}
		if details.Tags == nil {
			details.Tags = []string{}
		}

		if v3Data, ok := data.(libmodsecurityJSONMessageData); ok {
			details.Match = v3Data.Match()
			details.Reference = v3Data.Reference()
		}

		msg := message.Message()
		if msg == "" {
			msg = data.Msg()
		}

		formatted = append(formatted, libmodsecurityJSONMessage{
			Message: msg,
			Details: details,
		})
	}

	return formatted
}

func dashIfEmpty(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

var _ plugintypes.AuditLogFormatter = (*libmodsecurityJSONFormatter)(nil)
