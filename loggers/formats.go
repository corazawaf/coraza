// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package loggers implements a set of log formatters and writers
// for audit logging.
//
// The following log formats are supported:
//
// - JSON
// - Coraza
// - Native
//
// The following log writers are supported:
//
// - Serial
// - Concurrent
//
// More writers and formatters can be registered using the RegisterWriter and
// RegisterFormatter functions.
package loggers

import (
	"fmt"

	utils "github.com/corazawaf/coraza/v3/internal/strings"
)

func nativeFormatter(al *AuditLog) ([]byte, error) {
	boundary := utils.SafeRandom(10)
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
		parts['K'] += fmt.Sprintf("%s\n", r.Data.Raw)
	}
	parts['Z'] = ""
	data := ""
	for _, c := range []byte("ABCEFHKZ") {
		data += fmt.Sprintf("--%s-%c--\n%s\n", boundary, c, parts[c])
	}
	return []byte(data), nil
}

var (
	_ LogFormatter = nativeFormatter
)
