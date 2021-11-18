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
	"fmt"

	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
)

// Legacy modsecurity 2 format
func jsonFormatter(al AuditLog) ([]byte, error) {
	jsdata, err := json.Marshal(al)
	if err != nil {
		return nil, err
	}
	return jsdata, nil
}

// Coraza json format
func json2Formatter(al AuditLog) ([]byte, error) {
	reqHeaders := map[string]string{}
	for k, v := range al.Transaction.Request.Headers {
		reqHeaders[k] = v[0]
	}
	resHeaders := map[string]string{}
	for k, v := range al.Transaction.Response.Headers {
		resHeaders[k] = v[0]
	}
	al2 := auditLogLegacy{
		Transaction: auditLogLegacyTransaction{
			Time:          al.Transaction.Timestamp,
			TransactionID: al.Transaction.ID,
			RemoteAddress: al.Transaction.ClientIP,
			RemotePort:    al.Transaction.ClientPort,
			LocalAddress:  al.Transaction.HostIP,
			LocalPort:     al.Transaction.HostPort,
		},
		Request: auditLogLegacyRequest{
			RequestLine: fmt.Sprintf("%s %s %s", al.Transaction.Request.Method, al.Transaction.Request.URI, al.Transaction.Request.HTTPVersion),
			Headers:     reqHeaders,
		},
		Response: auditLogLegacyResponse{
			Status:   al.Transaction.Response.Status,
			Protocol: al.Transaction.Response.Protocol,
			Headers:  resHeaders,
		},
		AuditData: auditLogLegacyData{
			Stopwatch: auditLogLegacyStopwatch{},
		},
	}

	jsdata, err := json.Marshal(al2)
	if err != nil {
		return nil, err
	}
	return jsdata, nil
}

func cefFormatter(al AuditLog) ([]byte, error) {
	return nil, fmt.Errorf("CEF loggign not implemented yet (TBI)")
	/*
		TODO TBI
		f := make(map[string]string)
		f["src"] = al.Transaction.ClientIp
		f["status"] = strconv.Itoa(al.Transaction.Response.Status)
		// TODO add more fields
		timestamp := al.Transaction.Timestamp
		host := "localhost"
		m := &AuditMessage{}
		severity := "0"
		if len(al.Messages) > 0 {
			m = al.Messages[len(al.Messages)-1]
			severity = fmt.Sprintf("%d", m.Data.Severity)
		}
		msg := m.Message
		data := m.Data.Data

		if msg == "" {
			msg = "n/a"
		}
		if data == "" {
			data = "n/a"
		}
		if severity == "" {
			severity = "n/a"
		}
		ext := ""
		for k, v := range f {
			v := strings.ReplaceAll(v, "|", "\\|")
			ext += fmt.Sprintf("%s=%s ", k, v)
		}
		ext = strings.TrimSpace(ext)
		return fmt.Sprintf("%s %s CEF:0|coraza|coraza-waf|v1.2|%s|%s|%s|%s",
			timestamp,
			host,
			msg,
			data,
			severity,
			ext), nil*/
}

func nativeFormatter(al AuditLog) ([]byte, error) {
	boundary := utils.RandomString(10)
	parts := map[byte]string{}
	// [27/Jul/2016:05:46:16 +0200] V5guiH8AAQEAADTeJ2wAAAAK 192.168.3.1 50084 192.168.3.111 80
	parts['A'] = fmt.Sprintf("[%s] %s %s %d %s %d", al.Transaction.Timestamp, al.Transaction.ID,
		al.Transaction.ClientIP, al.Transaction.ClientPort, al.Transaction.HostIP, al.Transaction.HostPort)
	// GET /url HTTP/1.1
	// Host: example.com
	// User-Agent: Mozilla/5.0
	// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
	// Accept-Language: en-US,en;q=0.5
	// Accept-Encoding: gzip, deflate
	// Referer: http://example.com/index.html
	// Connection: keep-alive
	// Content-Type: application/x-www-form-urlencoded
	// Content-Length: 6
	parts['B'] = fmt.Sprintf("%s %s %s\n", al.Transaction.Request.Method, al.Transaction.Request.URI, al.Transaction.Request.Protocol)
	for k, vv := range al.Transaction.Request.Headers {
		for _, v := range vv {
			parts['B'] += fmt.Sprintf("%s: %s\n", k, v)
		}
	}
	// b=test
	parts['C'] = al.Transaction.Request.Body
	parts['E'] = al.Transaction.Response.Body
	parts['F'] = ""
	for k, vv := range al.Transaction.Response.Headers {
		for _, v := range vv {
			parts['F'] += fmt.Sprintf("%s: %s\n", k, v)
		}
	}
	// Stopwatch: 1470025005945403 1715 (- - -)
	// Stopwatch2: 1470025005945403 1715; combined=26, p1=0, p2=0, p3=0, p4=0, p5=26, ↩
	// sr=0, sw=0, l=0, gc=0
	// Response-Body-Transformed: Dechunked
	// Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/).
	// Server: Apache
	// Engine-Mode: "ENABLED"
	parts['H'] = fmt.Sprintf("Stopwatch: %s\nResponse-Body-Transformed: %s\nProducer: %s\nServer: %s", "", "", "", "")
	parts['K'] = ""
	for _, r := range al.Messages {
		parts['K'] = fmt.Sprintf("%s\n", r.Data.Raw)
	}
	parts['Z'] = ""
	data := ""
	for _, c := range []byte("ABCEFHKZ") {
		data += fmt.Sprintf("--%s-%c--\n%s\n", boundary, c, parts[c])
	}
	return []byte(data), nil
}

var (
	_ LogFormatter = cefFormatter
	_ LogFormatter = nativeFormatter
	_ LogFormatter = jsonFormatter
)
