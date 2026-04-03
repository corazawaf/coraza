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
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

type nativeFormatter struct{}

type auditLogWithErrMesg interface{ ErrorMessage() string }

func (nativeFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	if len(al.Parts()) == 0 {
		return nil, nil
	}

	boundaryPrefix := fmt.Sprintf("--%s-", utils.RandomString(10))

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
				al.Transaction().Timestamp(), al.Transaction().ID(),
				al.Transaction().ClientIP(), al.Transaction().ClientPort(),
				al.Transaction().HostIP(), al.Transaction().HostPort())
			addSeparator = false
		case types.AuditLogPartRequestHeaders:
			// Part B: Request headers
			if al.Transaction().HasRequest() {
				_, _ = fmt.Fprintf(
					&res,
					"%s %s %s",
					al.Transaction().Request().Method(),
					al.Transaction().Request().URI(),
					al.Transaction().Request().Protocol(),
				)
				for k, vv := range al.Transaction().Request().Headers() {
					for _, v := range vv {
						res.WriteByte('\n')
						res.WriteString(k)
						res.WriteString(": ")
						res.WriteString(v)
					}
				}
				res.WriteByte('\n')
			}
		case types.AuditLogPartRequestBody:
			// Part C: Request body
			if al.Transaction().HasRequest() {
				if body := al.Transaction().Request().Body(); body != "" {
					res.WriteString(body)
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartIntermediaryResponseBody:
			// Part E: Intermediary response body
			if al.Transaction().HasResponse() {
				if body := al.Transaction().Response().Body(); body != "" {
					res.WriteString(body)
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
				_, _ = fmt.Fprintf(&res, "%s %d %s\n", protocol, status, statusText)

				// Write headers
				for k, vv := range al.Transaction().Response().Headers() {
					for _, v := range vv {
						res.WriteString(k)
						res.WriteString(": ")
						res.WriteString(v)
						res.WriteByte('\n')
					}
				}
			}
		case types.AuditLogPartAuditLogTrailer:
			// Part H: Audit log trailer
			for _, alEntry := range al.Messages() {
				alWithErrMsg, ok := alEntry.(auditLogWithErrMesg)
				if ok && alWithErrMsg.ErrorMessage() != "" {
					res.WriteString(alWithErrMsg.ErrorMessage())
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartRulesMatched:
			// Part K: Matched rules
			for _, alEntry := range al.Messages() {
				res.WriteString(alEntry.Data().Raw())
				res.WriteByte('\n')
			}
		case types.AuditLogPartEndMarker:
			// Part Z: Final boundary marker with no content
		default:
			// For any other parts (D, G, I, J) that aren't explicitly handled,
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
