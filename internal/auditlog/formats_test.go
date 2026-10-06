// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

func checkLine(t *testing.T, lines []string, index int, expected string) {
	t.Helper()
	if lines[index] != expected {
		auditLog := &strings.Builder{}
		auditLog.WriteByte('\n')
		for i, line := range lines {
			fmt.Fprintf(auditLog, "Line %d: ", i)
			auditLog.WriteString(line)
			auditLog.WriteByte('\n')
		}
		t.Log(auditLog.String())
		t.Fatalf("unexpected line %d, \ngot: %q\nwant: %q\n", index, lines[index], expected)
	}
}

func mutateSeparator(separator string, part byte) string {
	return separator[:len(separator)-3] + string(part) + separator[len(separator)-2:]
}

func TestNativeFormatter(t *testing.T) {
	f := &nativeFormatter{}

	t.Run("empty parts", func(t *testing.T) {
		al := &Log{}
		l, err := f.Format(al)
		if l != nil {
			t.Error("expected nil log")
		}
		if err != nil {
			t.Error("unexpected error")
		}
	})

	t.Run("success", func(t *testing.T) {
		al := createAuditLog()
		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}
		if !strings.Contains(f.MIME(), "x-coraza-auditlog-native") {
			t.Errorf("failed to match MIME, expected json and got %s", f.MIME())
		}
		// Log contains random boundary strings
		if len(data) == 0 {
			t.Errorf("expected non-empty log output")
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))

		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		// Part B
		checkLine(t, lines, 0, mutateSeparator(separator, 'B'))
		checkLine(t, lines, 1, "GET /test.php HTTP/1.1")
		checkLine(t, lines, 2, "some: request header")
		checkLine(t, lines, 3, "")
		// Part C
		checkLine(t, lines, 4, mutateSeparator(separator, 'C'))
		checkLine(t, lines, 5, "some request body")
		checkLine(t, lines, 6, "")
		// Part E
		checkLine(t, lines, 7, mutateSeparator(separator, 'E'))
		checkLine(t, lines, 8, "some response body")
		checkLine(t, lines, 9, "")
		// Part F
		checkLine(t, lines, 10, mutateSeparator(separator, 'F'))
		checkLine(t, lines, 11, "HTTP/1.1 200 OK")
		checkLine(t, lines, 12, "some: response header")
		checkLine(t, lines, 13, "")
		// Part H
		checkLine(t, lines, 14, mutateSeparator(separator, 'H'))
		checkLine(t, lines, 15, "error message")
		checkLine(t, lines, 16, "")
		// Part K
		checkLine(t, lines, 17, mutateSeparator(separator, 'K'))
		checkLine(t, lines, 18, `SecAction "id:100"`)
		checkLine(t, lines, 19, "")
	})

	t.Run("with parts A and Z", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartHeader,
				types.AuditLogPartRequestHeaders,
				types.AuditLogPartEndMarker,
			},
			Transaction_: Transaction{
				Timestamp_:     "02/Jan/2006:15:04:20 -0700",
				UnixTimestamp_: 0,
				ID_:            "123",
				Request_: &TransactionRequest{
					URI_:    "/test.php",
					Method_: "GET",
					Headers_: map[string][]string{
						"some": {
							"request header",
						},
					},
					Protocol_: "HTTP/1.1",
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		// Part A (header) - no empty line after it
		checkLine(t, lines, 0, mutateSeparator(separator, 'A'))
		checkLine(t, lines, 1, "[02/Jan/2006:15:04:20 -0700] 123  0  0")

		// Part B (request headers) - has empty line after it
		checkLine(t, lines, 2, mutateSeparator(separator, 'B'))
		checkLine(t, lines, 3, "GET /test.php HTTP/1.1")
		checkLine(t, lines, 4, "some: request header")
		checkLine(t, lines, 5, "")

		// Part Z (end marker) - has empty line after it
		checkLine(t, lines, 6, mutateSeparator(separator, 'Z'))
		checkLine(t, lines, 7, "")
	})

	t.Run("complete example matching ModSecurity format", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartHeader,
				types.AuditLogPartRequestHeaders,
				types.AuditLogPartIntermediaryResponseHeaders, // Part D
				types.AuditLogPartResponseHeaders,             // Part F
				types.AuditLogPartAuditLogTrailer,             // Part H
				types.AuditLogPartEndMarker,
			},
			Transaction_: Transaction{
				Timestamp_:     "20/Feb/2025:13:20:33 +0000",
				UnixTimestamp_: 1740576033,
				ID_:            "174005763366.604533",
				ClientIP_:      "192.168.65.1",
				ClientPort_:    38532,
				HostIP_:        "172.21.0.3",
				HostPort_:      8080,
				Request_: &TransactionRequest{
					URI_:         "/status/200",
					Method_:      "GET",
					Protocol_:    "HTTP/1.1",
					HTTPVersion_: "1.1",
					Headers_: map[string][]string{
						"Accept":     {"*/*"},
						"Connection": {"close"},
						"Host":       {"localhost"},
					},
				},
				Response_: &TransactionResponse{
					Status_:   200,
					Protocol_: "HTTP/1.1",
					Headers_: map[string][]string{
						"Server":     {"nginx"},
						"Connection": {"close"},
					},
				},
			},
			Messages_: []plugintypes.AuditLogMessage{
				&Message{
					ErrorMessage_: "ModSecurity: Warning. Test message",
				},
			},
		}

		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}

		output := string(data)
		// Verify structure matches ModSecurity format
		if !bytes.Contains(data, []byte("174005763366.604533")) {
			t.Errorf("Missing transaction ID in output:\n%s", output)
		}
		if !bytes.Contains(data, []byte("GET /status/200 HTTP/1.1")) {
			t.Errorf("Missing request line in output:\n%s", output)
		}
		if !bytes.Contains(data, []byte("ModSecurity: Warning. Test message")) {
			t.Errorf("Missing error message in output:\n%s", output)
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		// Verify part A exists
		if !bytes.Contains(data, []byte("-A--")) {
			t.Error("Missing part A boundary")
		}
		// Verify part Z exists
		if !bytes.Contains(data, []byte("-Z--")) {
			t.Error("Missing part Z boundary")
		}
		// Verify part A has transaction info
		checkLine(t, lines, 1, "[20/Feb/2025:13:20:33 +0000] 174005763366.604533 192.168.65.1 38532 172.21.0.3 8080")
	})

	t.Run("apache example 1 - cookies and multiple messages", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartHeader,
				types.AuditLogPartRequestHeaders,
				types.AuditLogPartResponseHeaders,
				types.AuditLogPartIntermediaryResponseBody,
				types.AuditLogPartAuditLogTrailer,
				types.AuditLogPartEndMarker,
			},
			Transaction_: Transaction{
				Timestamp_:     "20/Feb/2025:15:15:26.453565 +0000",
				UnixTimestamp_: 1740064526,
				ID_:            "Z7dHDrSPGgnIk-ru4hvJcQAAAIA",
				ClientIP_:      "192.168.65.1",
				ClientPort_:    42378,
				HostIP_:        "172.22.0.3",
				HostPort_:      8080,
				Request_: &TransactionRequest{
					URI_:      "/",
					Method_:   "GET",
					Protocol_: "HTTP/1.1",
					Headers_: map[string][]string{
						"Accept":     {"*/*"},
						"Connection": {"close"},
						"Cookie":     {"$Version=1; session=\"deadbeef; PHPSESSID=secret; dummy=qaz\""},
						"Host":       {"localhost"},
						"Origin":     {"https://www.example.com"},
						"Referer":    {"https://www.example.com/"},
						"User-Agent": {"OWASP CRS test agent"},
					},
				},
				Response_: &TransactionResponse{
					Status_:   200,
					Protocol_: "HTTP/1.1",
					Headers_: map[string][]string{
						"Content-Length": {"0"},
						"Connection":     {"close"},
					},
				},
			},
			Messages_: []plugintypes.AuditLogMessage{
				&Message{
					ErrorMessage_: `Message: Warning. String match "1" at REQUEST_COOKIES:$Version. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf"] [line "332"] [id "921250"]`,
				},
				&Message{
					ErrorMessage_: `Message: Warning. Operator GE matched 5 at TX:blocking_inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "233"] [id "949110"]`,
				},
				&Message{
					ErrorMessage_: `Apache-Error: [file "apache2_util.c"] [line 275] [level 3] [client 192.168.65.1] ModSecurity: Warning.`,
				},
			},
		}

		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}

		output := string(data)
		// Verify key elements exist
		if !bytes.Contains(data, []byte("Z7dHDrSPGgnIk-ru4hvJcQAAAIA")) {
			t.Errorf("Missing transaction ID in output")
		}
		if !bytes.Contains(data, []byte("GET / HTTP/1.1")) {
			t.Errorf("Missing request line in output")
		}
		if !bytes.Contains(data, []byte("Cookie: $Version=1")) {
			t.Errorf("Missing cookie header in output")
		}
		if !bytes.Contains(data, []byte("HTTP/1.1 200")) {
			t.Errorf("Missing response status in output:\n%s", output)
		}
		// Verify multiple messages are present
		if !bytes.Contains(data, []byte("REQUEST-921-PROTOCOL-ATTACK.conf")) {
			t.Errorf("Missing first message in output")
		}
		if !bytes.Contains(data, []byte("REQUEST-949-BLOCKING-EVALUATION.conf")) {
			t.Errorf("Missing second message in output")
		}
		if !bytes.Contains(data, []byte("Apache-Error:")) {
			t.Errorf("Missing Apache-Error message in output")
		}

		// Verify parts A, B, F, E, H, Z exist
		if !bytes.Contains(data, []byte("-A--")) {
			t.Error("Missing part A")
		}
		if !bytes.Contains(data, []byte("-B--")) {
			t.Error("Missing part B")
		}
		if !bytes.Contains(data, []byte("-F--")) {
			t.Error("Missing part F")
		}
		if !bytes.Contains(data, []byte("-E--")) {
			t.Error("Missing part E")
		}
		if !bytes.Contains(data, []byte("-H--")) {
			t.Error("Missing part H")
		}
		if !bytes.Contains(data, []byte("-Z--")) {
			t.Error("Missing part Z")
		}
	})

	t.Run("apache example 2 - SQL injection with multiple rules", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartHeader,
				types.AuditLogPartRequestHeaders,
				types.AuditLogPartResponseHeaders,
				types.AuditLogPartIntermediaryResponseBody,
				types.AuditLogPartAuditLogTrailer,
				types.AuditLogPartEndMarker,
			},
			Transaction_: Transaction{
				Timestamp_:     "23/Feb/2025:22:40:32.479855 +0000",
				UnixTimestamp_: 1740350432,
				ID_:            "Z7uj4AkDMIUwf_JHM4k9hAAAAAY",
				ClientIP_:      "192.168.65.1",
				ClientPort_:    53953,
				HostIP_:        "172.21.0.3",
				HostPort_:      8080,
				Request_: &TransactionRequest{
					URI_:      "/get?var=sdfsd%27or%201%20%3e%201",
					Method_:   "GET",
					Protocol_: "HTTP/1.0",
					Headers_: map[string][]string{
						"Accept":     {"text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"},
						"Connection": {"close"},
						"Host":       {"localhost"},
						"User-Agent": {"OWASP CRS test agent"},
					},
				},
				Response_: &TransactionResponse{
					Status_:   200,
					Protocol_: "HTTP/1.1",
					Headers_: map[string][]string{
						"Content-Length": {"0"},
						"Connection":     {"close"},
					},
				},
			},
			Messages_: []plugintypes.AuditLogMessage{
				&Message{
					ErrorMessage_: `Message: Warning. Found 5 byte(s) in ARGS:var outside range: 38,44-46,48-58,61,65-90,95,97-122. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"] [line "1739"] [id "920273"]`,
				},
				&Message{
					ErrorMessage_: `Message: Warning. detected SQLi using libinjection with fingerprint 's&1' [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "66"] [id "942100"]`,
				},
				&Message{
					ErrorMessage_: `Message: Warning. Pattern match "(?i)(?:/\\*)+[\"'` + "`" + `]+[\\s\\x0b]?(?:--|[#\\{]|/\\*)?|[\"'` + "`" + `](?:[\\s\\x0b]*(?:(?:x?or|and|div|like|between)" at ARGS:var. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "822"] [id "942180"]`,
				},
				&Message{
					ErrorMessage_: `Message: Warning. Operator GE matched 5 at TX:blocking_inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "233"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 33)"]`,
				},
			},
		}

		data, err := f.Format(al)
		if err != nil {
			t.Error(err)
		}

		output := string(data)
		// Verify SQL injection detection messages
		if !bytes.Contains(data, []byte("Z7uj4AkDMIUwf_JHM4k9hAAAAAY")) {
			t.Errorf("Missing transaction ID")
		}
		if !bytes.Contains(data, []byte("/get?var=sdfsd%27or%201%20%3e%201")) {
			t.Errorf("Missing URI with SQL injection attempt")
		}
		if !bytes.Contains(data, []byte("libinjection")) {
			t.Errorf("Missing libinjection message")
		}
		if !bytes.Contains(data, []byte("920273")) {
			t.Errorf("Missing rule ID 920273")
		}
		if !bytes.Contains(data, []byte("942100")) {
			t.Errorf("Missing rule ID 942100")
		}
		if !bytes.Contains(data, []byte("942180")) {
			t.Errorf("Missing rule ID 942180")
		}
		if !bytes.Contains(data, []byte("Inbound Anomaly Score Exceeded (Total Score: 33)")) {
			t.Errorf("Missing anomaly score message")
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		// Verify the timestamp with microseconds
		if !bytes.Contains(data, []byte("[23/Feb/2025:22:40:32.479855 +0000]")) {
			t.Errorf("Missing timestamp with microseconds in output:\n%s", output)
		}

		// Verify part H contains all messages (they should be concatenated)
		partHFound := false
		for i, line := range lines {
			if strings.Contains(line, "-H--") {
				partHFound = true
				// Check that messages follow part H marker
				if i+1 < len(lines) {
					// At least one message should be present
					messagesFound := 0
					for j := i + 1; j < len(lines) && !strings.Contains(lines[j], "--"); j++ {
						if strings.Contains(lines[j], "Message:") {
							messagesFound++
						}
					}
					if messagesFound == 0 {
						t.Errorf("No messages found after part H marker")
					}
				}
				break
			}
		}
		if !partHFound {
			t.Error("Part H marker not found")
		}
	})
}

// hasLineContaining scans output line-by-line and returns true if any line
// exactly matches or contains the needle. This is the correct way to detect
// CRLF injection — a forged value should never appear as its own line.
func hasLineContaining(output, needle string) bool {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, needle) && !strings.Contains(line, `\r`) && !strings.Contains(line, `\n`) {
			return true
		}
	}
	return false
}

// TestNativeFormatterCRLFInjection verifies that CRLF sequences in attacker-controlled
// fields are escaped and cannot forge log boundaries or entries (GHSA-prpw-wwv7-xjjr).
func TestNativeFormatterCRLFInjection(t *testing.T) {
	f := &nativeFormatter{}

	t.Run("body with forged boundary", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartRequestBody,
			},
			Transaction_: Transaction{
				Request_: &TransactionRequest{
					Body_: "evil=benign\r\n--coraza-forged-X--\r\nForgedLine: yes\r\n--coraza-forged-H--\r\n[client \"9.9.9.9\"] FAKE ATTACK ENTRY",
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		// Count the lines — with escaping the body should be a single content line
		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		// Boundary line + escaped body line + empty separator = 3 lines
		if len(lines) != 3 {
			t.Errorf("expected 3 lines (boundary + escaped body + separator), got %d:\n%s", len(lines), string(data))
		}
		// The escaped form must be present as literal text
		if !strings.Contains(string(data), `\r\n--coraza-forged-X--`) {
			t.Error("expected escaped CRLF sequences in body output")
		}
	})

	t.Run("header value with CRLF", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartRequestHeaders,
			},
			Transaction_: Transaction{
				Request_: &TransactionRequest{
					Method_:   "GET",
					URI_:      "/",
					Protocol_: "HTTP/1.1",
					Headers_: map[string][]string{
						"X-Evil": {"value\r\nInjected-Header: malicious"},
					},
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		output := string(data)
		// The injected header must NOT appear as its own line
		if hasLineContaining(output, "Injected-Header: malicious") {
			t.Error("CRLF injection: injected header appeared as a separate line")
		}
		// The escaped form must be present
		if !strings.Contains(output, `value\r\nInjected-Header: malicious`) {
			t.Error("expected escaped CRLF sequences in header value")
		}
	})

	t.Run("response header with CRLF", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartResponseHeaders,
			},
			Transaction_: Transaction{
				Response_: &TransactionResponse{
					Status_:   200,
					Protocol_: "HTTP/1.1",
					Headers_: map[string][]string{
						"X-Evil": {"value\r\nInjected: yes"},
					},
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		output := string(data)
		if hasLineContaining(output, "Injected: yes") {
			t.Error("CRLF injection in response header value")
		}
		if !strings.Contains(output, `value\r\nInjected: yes`) {
			t.Error("expected escaped CRLF sequences in response header value")
		}
	})

	t.Run("error message with CRLF", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartAuditLogTrailer,
			},
			Transaction_: Transaction{},
			Messages_: []plugintypes.AuditLogMessage{
				&Message{
					ErrorMessage_: "real error\n[client \"9.9.9.9\"] FAKE ENTRY",
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		output := string(data)
		if hasLineContaining(output, `[client "9.9.9.9"] FAKE ENTRY`) {
			t.Error("CRLF injection in error message")
		}
		if !strings.Contains(output, `real error\n[client`) {
			t.Error("expected escaped newline in error message")
		}
	})

	t.Run("matched rule raw data with CRLF", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartRulesMatched,
			},
			Transaction_: Transaction{},
			Messages_: []plugintypes.AuditLogMessage{
				&Message{
					Data_: &MessageData{
						Raw_: "SecRule \"id:1\"\nSecRule \"id:9999\" # forged",
					},
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		output := string(data)
		if hasLineContaining(output, `SecRule "id:9999" # forged`) {
			t.Error("CRLF injection in matched rule raw data")
		}
		if !strings.Contains(output, `SecRule "id:1"\nSecRule "id:9999" # forged`) {
			t.Error("expected escaped newline in raw rule data")
		}
	})

	t.Run("response body with CRLF", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartIntermediaryResponseBody,
			},
			Transaction_: Transaction{
				Response_: &TransactionResponse{
					Body_: "legit body\r\n--fake-boundary-E--\r\nforged content",
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		output := string(data)
		if hasLineContaining(output, "--fake-boundary-E--") {
			t.Error("CRLF injection in response body")
		}
		if !strings.Contains(output, `legit body\r\n--fake-boundary-E--\r\nforged content`) {
			t.Error("expected escaped CRLF sequences in response body")
		}
	})
}

// TestNativeFormatterEscapeIsReversible verifies the escaper is injective: a
// real CR and the literal two-character input `\r` must not collide, or a
// consumer that unescapes turns the literal back into a line break and the
// injection survives the round trip (GHSA-prpw-wwv7-xjjr).
func TestNativeFormatterEscapeIsReversible(t *testing.T) {
	realCRLF := logEscaper.Replace("evil\r\nForged: yes")
	literal := logEscaper.Replace(`evil\r\nForged: yes`)

	if realCRLF == literal {
		t.Errorf("escaping is not reversible: a real CRLF and the literal %q both render as %q",
			`\r\n`, realCRLF)
	}
	if strings.ContainsAny(realCRLF, "\r\n") {
		t.Errorf("real control characters survived escaping: %q", realCRLF)
	}
	// The literal backslashes must be doubled, not left alone.
	if !strings.Contains(literal, `\\r`) {
		t.Errorf("literal backslash was not escaped: %q", literal)
	}
	// A single left-to-right pass must not re-scan its own output.
	if got := logEscaper.Replace(`a\b`); got != `a\\b` {
		t.Errorf("double escaping: %q -> %q", `a\b`, got)
	}
}

// lineCount reports how many lines a formatted record occupies. Injection into
// any field shows up as extra lines, which is a stronger check than scanning
// for a needle: hasLineContaining treats a line holding any escaped `\r` as
// safe, so it misses a forged line that shares a line with an escaped field.
func lineCount(t *testing.T, data []byte) int {
	t.Helper()
	return len(strings.Split(strings.TrimRight(string(data), "\n"), "\n"))
}

// TestNativeFormatterEscapesNonBodyFields covers the fields that are not
// request or response bodies: the Part A transaction line, the Part B request
// line, and header names in Parts B and F. All are caller-supplied. Each case
// formats a benign record and a hostile one and requires the same line count --
// a field that escapes its line changes that count.
func TestNativeFormatterEscapesNonBodyFields(t *testing.T) {
	f := &nativeFormatter{}
	const evil = "\r\nForged: yes"

	tests := []struct {
		name            string
		part            types.AuditLogPart
		benign, hostile Transaction
	}{
		{
			name: "part A transaction id and IPs",
			part: types.AuditLogPartHeader,
			benign: Transaction{
				ID_: "id", ClientIP_: "1.1.1.1", HostIP_: "2.2.2.2",
			},
			hostile: Transaction{
				ID_:       "id" + evil,
				ClientIP_: "1.1.1.1" + evil,
				HostIP_:   "2.2.2.2" + evil,
			},
		},
		{
			name: "part B request line and header name",
			part: types.AuditLogPartRequestHeaders,
			benign: Transaction{Request_: &TransactionRequest{
				Method_: "GET", URI_: "/a", Protocol_: "HTTP/1.1",
				Headers_: map[string][]string{"X-Test": {"v"}},
			}},
			hostile: Transaction{Request_: &TransactionRequest{
				Method_: "GET" + evil, URI_: "/a" + evil, Protocol_: "HTTP/1.1" + evil,
				Headers_: map[string][]string{"X-Test" + evil: {"v"}},
			}},
		},
		{
			name: "part F status line and header name",
			part: types.AuditLogPartResponseHeaders,
			benign: Transaction{Response_: &TransactionResponse{
				Protocol_: "HTTP/1.1", Status_: 200,
				Headers_: map[string][]string{"X-Test": {"v"}},
			}},
			hostile: Transaction{Response_: &TransactionResponse{
				Protocol_: "HTTP/1.1" + evil, Status_: 200,
				Headers_: map[string][]string{"X-Test" + evil: {"v"}},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			format := func(tr Transaction) []byte {
				data, err := f.Format(&Log{Parts_: []types.AuditLogPart{tc.part}, Transaction_: tr})
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			want := lineCount(t, format(tc.benign))
			got := lineCount(t, format(tc.hostile))
			if got != want {
				t.Errorf("hostile input added %d line(s); a field escaped its line:\n%s", got-want, format(tc.hostile))
			}
			if strings.Contains(string(format(tc.hostile)), "\nForged: yes") {
				t.Errorf("forged header appears on its own line:\n%s", format(tc.hostile))
			}
		})
	}
}

func TestNativeFormatterPartJ(t *testing.T) {
	f := &nativeFormatter{}

	t.Run("uploaded files", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartUploadedFiles,
			},
			Transaction_: Transaction{
				Request_: &TransactionRequest{
					Files_: []plugintypes.AuditLogTransactionRequestFiles{
						TransactionRequestFiles{Name_: "image.png", Size_: 12345, Mime_: "image/png"},
						TransactionRequestFiles{Name_: "doc.pdf", Size_: 67890, Mime_: "application/pdf"},
					},
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		checkLine(t, lines, 0, mutateSeparator(separator, 'J'))
		checkLine(t, lines, 1, `1,12345,"image.png","image/png"`)
		checkLine(t, lines, 2, `2,67890,"doc.pdf","application/pdf"`)
		checkLine(t, lines, 3, `Total,80235`)
		checkLine(t, lines, 4, "")
	})

	t.Run("no files", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartUploadedFiles,
			},
			Transaction_: Transaction{
				Request_: &TransactionRequest{},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		checkLine(t, lines, 0, mutateSeparator(separator, 'J'))
		checkLine(t, lines, 1, "Total,0")
		checkLine(t, lines, 2, "")
	})

	t.Run("unknown content type", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartUploadedFiles,
			},
			Transaction_: Transaction{
				Request_: &TransactionRequest{
					Files_: []plugintypes.AuditLogTransactionRequestFiles{
						TransactionRequestFiles{Name_: "mystery", Size_: 100, Mime_: ""},
					},
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		checkLine(t, lines, 0, mutateSeparator(separator, 'J'))
		checkLine(t, lines, 1, `1,100,"mystery","<Unknown Content-Type>"`)
		checkLine(t, lines, 2, "Total,100")
	})

	t.Run("filename with special characters", func(t *testing.T) {
		al := &Log{
			Parts_: []types.AuditLogPart{
				types.AuditLogPartUploadedFiles,
			},
			Transaction_: Transaction{
				Request_: &TransactionRequest{
					Files_: []plugintypes.AuditLogTransactionRequestFiles{
						TransactionRequestFiles{Name_: "file \"quoted\".txt", Size_: 50, Mime_: "text/plain"},
					},
				},
			},
		}
		data, err := f.Format(al)
		if err != nil {
			t.Fatal(err)
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		separator := lines[0]

		checkLine(t, lines, 0, mutateSeparator(separator, 'J'))
		checkLine(t, lines, 1, `1,50,"file \"quoted\".txt","text/plain"`)
		checkLine(t, lines, 2, "Total,50")
	})
}

func createAuditLog() *Log {
	return &Log{
		Parts_: []types.AuditLogPart{
			types.AuditLogPartRequestHeaders,
			types.AuditLogPartRequestBody,
			types.AuditLogPartIntermediaryResponseBody,
			types.AuditLogPartResponseHeaders,
			types.AuditLogPartAuditLogTrailer,
			types.AuditLogPartRulesMatched,
		},
		Transaction_: Transaction{
			Timestamp_:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp_: 0,
			ID_:            "123",
			Request_: &TransactionRequest{
				URI_:    "/test.php",
				Method_: "GET",
				Headers_: map[string][]string{
					"some": {
						"request header",
					},
				},
				Body_:     "some request body",
				Protocol_: "HTTP/1.1",
			},
			Response_: &TransactionResponse{
				Status_: 200,
				Headers_: map[string][]string{
					"some": {
						"response header",
					},
				},
				Body_: "some response body",
			},
			Producer_: &TransactionProducer{
				Connector_: "some connector",
				Version_:   "1.2.3",
			},
		},
		Messages_: []plugintypes.AuditLogMessage{
			&Message{
				Message_:      "some message",
				ErrorMessage_: "error message",
				Data_: &MessageData{
					Msg_: "some message",
					Raw_: "SecAction \"id:100\"",
				},
			},
		},
	}
}
