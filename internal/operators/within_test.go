package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestNewWithin(t *testing.T) {
	op, err := newWithin(plugintypes.OperatorOptions{Arguments: "GET,POST,HEAD"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	waf := corazawaf.NewWAF()
	tx := waf.NewTransaction()
	if want, have := true, op.Evaluate(tx, "GET"); want != have {
		t.Fatalf("unexpected value: want %T, have %T", want, have)
	}

	if want, have := false, op.Evaluate(tx, "OPTIONS"); want != have {
		t.Fatalf("unexpected value: want %T, have %T", want, have)
	}

	if want, have := false, op.Evaluate(tx, "GE"); want != have {
		t.Fatalf("unexpected value: want %T, have %T", want, have)
	}
}
