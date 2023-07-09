package e2e

import "testing"

func TestSetHTTPSchemeIfMissing(t *testing.T) {
	tests := map[string]struct {
		rawURL      string
		expectedURL string
	}{
		"empty":         {rawURL: "", expectedURL: ""},
		"path":          {rawURL: "abc", expectedURL: "http://abc"},
		"path and port": {rawURL: "abc:123", expectedURL: "http://abc:123"},
		"no schema":     {rawURL: "://localhost:123/", expectedURL: "://localhost:123/"},
		"with schema":   {rawURL: "http://1.2.3.4:8080/abc", expectedURL: "http://1.2.3.4:8080/abc"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			url := setHTTPSchemeIfMissing(test.rawURL)
			if want, have := test.expectedURL, url; want != have {
				t.Errorf("unexpected URL, want %q, have %q", want, have)
			}
		})
	}
}
