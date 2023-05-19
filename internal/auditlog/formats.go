// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package auditlog implements a set of log formatters and writers
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
package auditlog

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

func nativeFormatter(al plugintypes.AuditLog) ([]byte, error) {
	boundaryPrefix := fmt.Sprintf("--%s-", utils.RandomString(10))

	var res strings.Builder

	for _, part := range al.Parts() {
		res.WriteString(boundaryPrefix)
		res.WriteByte(byte(part))
		res.WriteString("--\n")
		switch part {
		case types.AuditLogPartAuditLogHeader:
			// [27/Jul/2016:05:46:16 +0200] V5guiH8AAQEAADTeJ2wAAAAK 192.168.3.1 50084 192.168.3.111 80
			_, _ = fmt.Fprintf(&res, "[%s] %s %s %d %s %d", al.Transaction().Timestamp(), al.Transaction().ID(),
				al.Transaction().ClientIP(), al.Transaction().ClientPort(), al.Transaction().HostIP(), al.Transaction().HostPort())
		case types.AuditLogPartRequestHeaders:
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
			_, _ = fmt.Fprintf(
				&res,
				"%s %s %s\n",
				al.Transaction().Request().Method(),
				al.Transaction().Request().URI(),
				al.Transaction().Request().Protocol(),
			)
			for k, vv := range al.Transaction().Request().Headers() {
				for _, v := range vv {
					res.WriteString(k)
					res.WriteString(": ")
					res.WriteString(v)
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartRequestBody:
			// b=test
			res.WriteString(al.Transaction().Request().Body())
		case types.AuditLogPartIntermediaryResponseBody:
			res.WriteString(al.Transaction().Response().Body())
		case types.AuditLogPartResponseHeaders:
			for k, vv := range al.Transaction().Response().Headers() {
				for _, v := range vv {
					res.WriteString(k)
					res.WriteString(": ")
					res.WriteString(v)
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartAuditLogTrailer:
			// Stopwatch: 1470025005945403 1715 (- - -)
			// Stopwatch2: 1470025005945403 1715; combined=26, p1=0, p2=0, p3=0, p4=0, p5=26, ↩
			// sr=0, sw=0, l=0, gc=0
			// Response-Body-Transformed: Dechunked
			// Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/).
			// Server: Apache
			// Engine-Mode: "ENABLED"
			_, _ = fmt.Fprintf(&res, "Stopwatch: %s\nResponse-Body-Transformed: %s\nProducer: %s\nServer: %s", "", "", "", "")
		case types.AuditLogPartRulesMatched:
			for _, r := range al.Messages() {
				res.WriteString(r.Data().Raw())
				res.WriteByte('\n')
			}
		}
		res.WriteByte('\n')
	}

	return []byte(res.String()), nil
}

var (
	_ plugintypes.AuditLogFormatter = nativeFormatter
)
