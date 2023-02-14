package actions

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestLogInit(t *testing.T) {
	action := log()
	r := &corazawaf.Rule{}
	err := action.Init(r, "")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if want, have := true, r.Log; want != have {
		t.Errorf("unexpected log value, want %t, have %t", want, have)
	}

	if want, have := true, r.Audit; want != have {
		t.Errorf("unexpected audit value, want %t, have %t", want, have)
	}
}
