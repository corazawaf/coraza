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
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

// logEscaper neutralizes CR/LF sequences in attacker-controlled fields
// to prevent CRLF injection and log forgery in the Native audit log format.
// See GHSA-prpw-wwv7-xjjr.
//
// The backslash is escaped first so the mapping stays reversible: without it a
// real CR and the literal two-character input `\r` both render as `\r`, and a
// consumer that unescapes would turn the literal back into a line break --
// re-materialising the break this is meant to neutralise. Replacer makes a
// single left-to-right pass and never re-scans its own output, so escaping the
// backslash cannot double-escape.
var logEscaper = strings.NewReplacer(`\`, `\\`, "\r", `\r`, "\n", `\n`)

type nativeFormatter struct{}

type auditLogWithErrMesg interface{ ErrorMessage() string }

func (nativeFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	if len(al.Parts()) == 0 {
		return nil, nil
	}

	boundaryPrefix := fmt.Sprintf("--%s-", utils.RandomString(16))

	var res strings.Builder

	for _, part := range al.Parts() {
		res.WriteString(boundaryPrefix)
		res.WriteByte(byte(part))
		res.WriteString("--\n")

		addSeparator := true

		switch part {
		case types.AuditLogPartHeader:
			// Part A: Audit log header containing only the timestamp and transaction info line
			// Note: Part A does not have an empty line separator after it
			_, _ = fmt.Fprintf(&res, "[%s] %s %s %d %s %d\n",
				al.Transaction().Timestamp(), logEscaper.Replace(al.Transaction().ID()),
				logEscaper.Replace(al.Transaction().ClientIP()), al.Transaction().ClientPort(),
				logEscaper.Replace(al.Transaction().HostIP()), al.Transaction().HostPort())
			addSeparator = false
		case types.AuditLogPartRequestHeaders:
			// Part B: Request headers
			if al.Transaction().HasRequest() {
				_, _ = fmt.Fprintf(
					&res,
					"%s %s %s",
					logEscaper.Replace(al.Transaction().Request().Method()),
					logEscaper.Replace(al.Transaction().Request().URI()),
					logEscaper.Replace(al.Transaction().Request().Protocol()),
				)
				for k, vv := range al.Transaction().Request().Headers() {
					for _, v := range vv {
						res.WriteByte('\n')
						res.WriteString(logEscaper.Replace(k))
						res.WriteString(": ")
						res.WriteString(logEscaper.Replace(v))
					}
				}
				res.WriteByte('\n')
			}
		case types.AuditLogPartRequestBody:
			// Part C: Request body
			if al.Transaction().HasRequest() {
				if body := al.Transaction().Request().Body(); body != "" {
					res.WriteString(logEscaper.Replace(body))
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartIntermediaryResponseBody:
			// Part E: Intermediary response body
			if al.Transaction().HasResponse() {
				if body := al.Transaction().Response().Body(); body != "" {
					res.WriteString(logEscaper.Replace(body))
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartResponseHeaders:
			// Part F: Response headers
			if al.Transaction().HasResponse() {
				// Write status line: HTTP/1.1 200 OK
				protocol := al.Transaction().Response().Protocol()
				if protocol == "" {
					protocol = "HTTP/1.1"
				}
				status := al.Transaction().Response().Status()
				statusText := http.StatusText(status)
				_, _ = fmt.Fprintf(&res, "%s %d %s\n", logEscaper.Replace(protocol), status, statusText)

				// Write headers
				for k, vv := range al.Transaction().Response().Headers() {
					for _, v := range vv {
						res.WriteString(logEscaper.Replace(k))
						res.WriteString(": ")
						res.WriteString(logEscaper.Replace(v))
						res.WriteByte('\n')
					}
				}
			}
		case types.AuditLogPartAuditLogTrailer:
			// Part H: Audit log trailer
			for _, alEntry := range al.Messages() {
				alWithErrMsg, ok := alEntry.(auditLogWithErrMesg)
				if ok && alWithErrMsg.ErrorMessage() != "" {
					res.WriteString(logEscaper.Replace(alWithErrMsg.ErrorMessage()))
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartUploadedFiles:
			// Part J: Uploaded files information
			// Format matches ModSecurity v2: index,size,"filename","content_type"
			if al.Transaction().HasRequest() {
				files := al.Transaction().Request().Files()
				var totalSize int64
				for i, file := range files {
					contentType := file.Mime()
					if contentType == "" {
						contentType = "<Unknown Content-Type>"
					}
					_, _ = fmt.Fprintf(&res, "%d,%d,%s,%s\n",
						i+1, file.Size(),
						strconv.Quote(file.Name()),
						strconv.Quote(contentType))
					totalSize += file.Size()
				}
				_, _ = fmt.Fprintf(&res, "Total,%d\n", totalSize)
			}
		case types.AuditLogPartRulesMatched:
			// Part K: Matched rules
			for _, alEntry := range al.Messages() {
				res.WriteString(logEscaper.Replace(alEntry.Data().Raw()))
				res.WriteByte('\n')
			}
		case types.AuditLogPartEndMarker:
			// Part Z: Final boundary marker with no content
		default:
			// For any other parts (D, G, I) that aren't explicitly handled,
			// they remain empty
		}

		// Add separator newline for all parts except A
		if addSeparator {
			res.WriteByte('\n')
		}
	}

	return []byte(res.String()), nil
}

func (nativeFormatter) MIME() string {
	return "application/x-coraza-auditlog-native"
}

var (
	_ plugintypes.AuditLogFormatter = (*nativeFormatter)(nil)
)
