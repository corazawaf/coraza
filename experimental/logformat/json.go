package logformat

import (
	"encoding/json"

	"github.com/corazawaf/coraza/v3/types"
)

type ErrorLogData struct {
	Accuracy   int             `json:"accuracy"`
	Client     string          `json:"client"`
	Data       string          `json:"data"`
	Disruptive bool            `json:"disruptive"`
	File       string          `json:"file"`
	Line       int             `json:"line"`
	Maturity   int             `json:"maturity"`
	Msg        string          `json:"msg"`
	Phase      types.RulePhase `json:"phase"`
	Revision   string          `json:"revision"`
	RuleID     int             `json:"rule_id"`
	Server     string          `json:"server"`
	Severity   string          `json:"severity"`
	SeverityID int             `json:"severity_id"`
	Tags       []string        `json:"tags"`
	URI        string          `json:"uri"`
	UniqueID   string          `json:"unique_id"`
	Version    string          `json:"version"`
}

// ErrorLogJSON returns the matched rule error log as a JSON byte slice.
func ErrorLogJSON(mr types.MatchedRule) ([]byte, error) {
	r := mr.Rule()
	return json.Marshal(ErrorLogData{
		Accuracy:   r.Accuracy(),
		Client:     mr.ClientIPAddress(),
		Data:       mr.Data(),
		Disruptive: mr.Disruptive(),
		File:       r.File(),
		Line:       r.Line(),
		Maturity:   r.Maturity(),
		Msg:        mr.Message(),
		Phase:      r.Phase(),
		Revision:   r.Revision(),
		RuleID:     r.ID(),
		Server:     mr.ServerIPAddress(),
		Severity:   r.Severity().String(),
		SeverityID: r.Severity().Int(),
		Tags:       r.Tags(),
		URI:        mr.URI(),
		UniqueID:   mr.TransactionID(),
		Version:    r.Version(),
	})
}
