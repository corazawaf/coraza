package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazatypes"
)

func TestAllowInit(t *testing.T) {
	for _, test := range []struct {
		data              string
		expectedAllowType corazatypes.AllowType
	}{
		{"", corazatypes.AllowTypeAll},
		{"phase", corazatypes.AllowTypePhase},
		{"request", corazatypes.AllowTypeRequest},
	} {
		t.Run(test.data, func(t *testing.T) {
			a := allow()
			if err := a.Init(nil, test.data); err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if want, have := a.(*allowFn).allow, test.expectedAllowType; want != have {
				t.Errorf("unexpected allow type, want: %d, have: %d", want, have)
			}
		})
	}

	t.Run("invalid", func(t *testing.T) {
		if err := allow().Init(nil, "response"); err == nil {
			t.Errorf("expected error")
		}
	})
}
