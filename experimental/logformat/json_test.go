package logformat_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/logformat"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
)

func TestErrorLogJSON(t *testing.T) {
	matchedRule := &corazarules.MatchedRule{
		Message_:         "Restricted File Access Attempt",
		Data_:            "Matched Data: .env found within REQUEST_FILENAME: /.env",
		URI_:             "/.env",
		TransactionID_:   "b9453dc8-4bd6-4c5a-9257-8787906ed0ba",
		Disruptive_:      true,
		ServerIPAddress_: "10.10.10.0",
		ClientIPAddress_: "99.99.99.99",
		Rule_: &corazarules.RuleMetadata{
			ID_:       930130,
			File_:     "@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
			Line_:     4642,
			Rev_:      "",
			Severity_: types.RuleSeverityCritical,
			Version_:  "OWASP_CRS/4.23.0",
			Tags_:     []string{"application-multi", "language-multi", "platform-multi", "attack-lfi", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-LFI", "capec/1000/255/153/126"},
			Maturity_: 0,
			Accuracy_: 0,
			Phase_:    types.PhaseRequestHeaders,
		},
	}

	jsonData, err := logformat.ErrorLogJSON(matchedRule)
	if err != nil {
		t.Fatalf("ErrorLogJSON returned error: %v", err)
	}
	var log logformat.ErrorLogData
	if err := json.Unmarshal(jsonData, &log); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	expected := logformat.ErrorLogData{
		Accuracy:   0,
		Client:     "99.99.99.99",
		Data:       "Matched Data: .env found within REQUEST_FILENAME: /.env",
		Disruptive: true,
		File:       "@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
		Line:       4642,
		Maturity:   0,
		Msg:        "Restricted File Access Attempt",
		Phase:      types.PhaseRequestHeaders,
		Revision:   "",
		RuleID:     930130,
		Server:     "10.10.10.0",
		Severity:   "critical",
		SeverityID: 2,
		Tags:       []string{"application-multi", "language-multi", "platform-multi", "attack-lfi", "paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-LFI", "capec/1000/255/153/126"},
		URI:        "/.env",
		UniqueID:   "b9453dc8-4bd6-4c5a-9257-8787906ed0ba",
		Version:    "OWASP_CRS/4.23.0",
	}

	if !reflect.DeepEqual(log, expected) {
		t.Errorf("Expected %+v, got %+v", expected, log)
	}
}
