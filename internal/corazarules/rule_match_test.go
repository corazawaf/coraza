// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazarules

import (
	"strings"
	"testing"

	"github.com/redwanghb/coraza/v3/internal/variables"
	"github.com/redwanghb/coraza/v3/types"
)

func TestErrorLogMessagesSizesNoExtraRuleDetails(t *testing.T) {
	matchedRule := &MatchedRule{
		Rule_: &RuleMetadata{
			ID_: 1234,
		},
		MatchedDatas_: []types.MatchData{
			&MatchData{
				Variable_: variables.RequestURI,
				Key_:      "REQUEST_URI",
				Value_:    "/",
				Message_:  "",
				Data_:     "",
			},
		},
	}
	LogSizeWithoutMsg := len(matchedRule.ErrorLog())
	matchedRule.MatchedDatas_[0].(*MatchData).Message_ = strings.Repeat("a", 300)
	logWithMsg := matchedRule.ErrorLog()
	logSizeWithMsg := len(logWithMsg)
	// The parent message is repeated twice when logging error log
	if lenDiff := logSizeWithMsg - LogSizeWithoutMsg; lenDiff != maxSizeLogMessage*2 {
		t.Errorf("Expected message repeated twice with total len equal to %d, got %d", maxSizeLogMessage*2, lenDiff)
	}
	matchedRule.MatchedDatas_[0].(*MatchData).Data_ = strings.Repeat("b", 300)
	logWithMsgData := matchedRule.ErrorLog()
	logSizeWithMsgData := len(logWithMsgData)
	if lenDiff := logSizeWithMsgData - logSizeWithMsg; lenDiff != maxSizeLogMessage {
		t.Errorf("Expected data message with len equal to %d, got %d", maxSizeLogMessage, lenDiff)
	}
}
func TestErrorLogMessages(t *testing.T) {
	matchedRule := &MatchedRule{
		Rule_: &RuleMetadata{
			ID_: 1234,
		},
		MatchedDatas_: []types.MatchData{
			&MatchData{
				Variable_: variables.RequestURI,
				Key_:      "REQUEST_URI",
				Value_:    "/",
				Message_:  "",
				Data_:     "",
			},
		},
	}
	testCases := map[string]struct {
		disruptive       bool
		disruptiveAction DisruptiveAction
		expectedLogLine  string
	}{
		"no disruptive action": {
			disruptive:      false,
			expectedLogLine: "Coraza: Warning.",
		},
		"Deny disruptive action": {
			disruptive:       true,
			disruptiveAction: DisruptiveActionDeny,
			expectedLogLine:  "Coraza: Access denied",
		},
		"Allow disruptive action": {
			disruptive:       true,
			disruptiveAction: DisruptiveActionAllow,
			expectedLogLine:  "Coraza: Access allowed",
		},
		"Drop disruptive action": {
			disruptive:       true,
			disruptiveAction: DisruptiveActionDrop,
			expectedLogLine:  "Coraza: Access dropped",
		},
		"Pass disruptive action": {
			disruptive:       true,
			disruptiveAction: DisruptiveActionPass,
			expectedLogLine:  "Coraza: Warning.",
		},
		"Redirect disruptive action": {
			disruptive:       true,
			disruptiveAction: DisruptiveActionRedirect,
			expectedLogLine:  "Coraza: Access redirected",
		},
		"Custom disruptive action": {
			disruptive:       true,
			disruptiveAction: DisruptiveActionUnknown,
			expectedLogLine:  "Coraza: Custom disruptive action",
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			matchedRule.Disruptive_ = tCase.disruptive
			if tCase.disruptive {
				matchedRule.DisruptiveAction_ = tCase.disruptiveAction
			}
			logLine := matchedRule.ErrorLog()
			if !strings.Contains(logLine, tCase.expectedLogLine) {
				t.Errorf("Expected string \"%s\", got %s", tCase.expectedLogLine, logLine)
			}
		})
	}
}

func TestErrorLogMessagesSizesWithExtraRuleDetails(t *testing.T) {
	matchedRule := &MatchedRule{
		Rule_: &RuleMetadata{
			ID_: 1234,
		},
		MatchedDatas_: []types.MatchData{
			&MatchData{
				Variable_: variables.RequestURI,
				Key_:      "REQUEST_URI",
				Value_:    "/",
				Message_:  " ",
				Data_:     " ",
			},
			&MatchData{
				Variable_: variables.RequestURI,
				Key_:      "REQUEST_URI",
				Value_:    "/",
				Message_:  strings.Repeat("c", 300),
				Data_:     "",
			},
		},
	}
	logWithExtraMsg := matchedRule.ErrorLog()
	expectedExtraMsgLine := "\"" + strings.Repeat("c", maxSizeLogMessage) + "\""
	if !strings.Contains(logWithExtraMsg, expectedExtraMsgLine) {
		t.Errorf("Expected \"%s\" in log string, got %s", expectedExtraMsgLine, logWithExtraMsg)
	}

	matchedRule.MatchedDatas_[1].(*MatchData).Data_ = strings.Repeat("d", 300)
	logWithExtraMsgData := matchedRule.ErrorLog()

	expectedExtraDataLine := "\"" + strings.Repeat("d", maxSizeLogMessage) + "\""
	if !strings.Contains(logWithExtraMsgData, expectedExtraDataLine) {
		t.Errorf("Expected \"%s\" in log string, got %s", expectedExtraDataLine, logWithExtraMsgData)
	}

	extraMsgLine := "msg_match_"
	if !strings.Contains(logWithExtraMsg, extraMsgLine) {
		t.Errorf("Expected \"%s\" in log string, got %s", extraMsgLine, extraMsgLine)
	}
	extraDataLine := "data_match_"
	if !strings.Contains(logWithExtraMsgData, extraDataLine) {
		t.Errorf("Expected \"%s\" in log string, got %s", extraDataLine, extraDataLine)
	}
}
