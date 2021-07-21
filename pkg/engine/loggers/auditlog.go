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

package loggers

import (
	"encoding/json"
)

// Main struct for audit log data
type AuditLog struct {
	// Transaction information
	Transaction *AuditTransaction `json:"transaction"`

	// Triggered rules information
	Messages []*AuditMessage `json:"messages"`
}

// Transaction information
type AuditTransaction struct {
	// Timestamp "02/Jan/2006:15:04:20 -0700" format
	Timestamp     string `json:"timestamp"`
	UnixTimestamp int64  `json:"unix_timestamp"`

	// Unique ID
	Id string `json:"id"`

	// Client IP Address string representation
	ClientIp string `json:"client_ip"`

	ClientPort int                       `json:"client_port"`
	HostIp     string                    `json:"host_ip"`
	HostPort   int                       `json:"host_port"`
	ServerId   string                    `json:"server_id"`
	Request    *AuditTransactionRequest  `json:"request"`
	Response   *AuditTransactionResponse `json:"response"`
	Producer   *AuditTransactionProducer `json:"producer"`
}

type AuditTransactionResponse struct {
	Status  int
	Headers map[string][]string
	Body    string
}

type AuditTransactionProducer struct {
	Connector  string `json:"connector"`
	Version    string `json:"version"`
	Server     string `json:"server"`
	RuleEngine string `json:"rule_engine"`
	Stopwatch  string `json:"stopwatch"`
}

type AuditTransactionRequest struct {
	Method      string                          `json:"method"`
	Protocol    string                          `json:"protocol"`
	Uri         string                          `json:"uri"`
	HttpVersion string                          `json:"http_version"`
	Headers     map[string][]string             `json:"headers"`
	Body        string                          `json:"body"`
	Files       []*AuditTransactionRequestFiles `json:"files"`
}

type AuditTransactionRequestFiles struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Mime string `json:"mime"`
}

type AuditMessage struct {
	Actionset string            `json:"actionset"`
	Message   string            `json:"message"`
	Data      *AuditMessageData `json:"data"`
}

type AuditMessageData struct {
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Id       int      `json:"id"`
	Rev      string   `json:"rev"`
	Msg      string   `json:"msg"`
	Data     string   `json:"data"`
	Severity int      `json:"severity"`
	Ver      string   `json:"ver"`
	Maturity int      `json:"maturity"`
	Accuracy int      `json:"accuracy"`
	Tags     []string `json:"tags"`
}

func (al *AuditLog) JSON() ([]byte, error) {
	return json.Marshal(al)
}
