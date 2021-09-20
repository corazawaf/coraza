package loggers

import "testing"

func TestFormatters(t *testing.T) {
	al := &AuditLog{
		Transaction: &AuditTransaction{
			Timestamp:     "02/Jan/2006:15:04:20 -0700",
			UnixTimestamp: 0,
			Id:            "123",
			Request: &AuditTransactionRequest{
				Uri:    "/test.php",
				Method: "GET",
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
			Response: &AuditTransactionResponse{
				Headers: map[string][]string{
					"some": {
						"somedata",
					},
				},
			},
		},
		Messages: []*AuditMessage{
			{
				Data: &AuditMessageData{},
			},
		},
	}
	type tcase struct {
		AuditLog *AuditLog
		Output   string
	}
	cases := map[string][]tcase{
		"cef": {
			{al, "02/Jan/2006:15:04:20 -0700 localhost CEF:0|coraza|coraza-waf|v1.2|n/a|n/a|0|src= status=0"},
		},
	}

	for format, cases := range cases {
		f, err := getFormatter(format)
		if err != nil {
			t.Error(err)
		}
		for _, c := range cases {
			if out, err := f(c.AuditLog); err != nil {
				t.Error(err)
			} else if out != c.Output {
				t.Errorf("failed to match log formatter %s, got %s", format, out)
			}
		}
	}
}
