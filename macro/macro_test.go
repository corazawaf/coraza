package macro

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestNewMacro(t *testing.T) {
	_, err := NewMacro("some string")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestCompile(t *testing.T) {
	t.Run("empty data", func(t *testing.T) {
		m := &macro{}
		err := m.compile("")
		if err == nil || err.Error() != "empty macro" {
			t.Errorf("expected error: empty macro")
		}
	})

	t.Run("malformed macro", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.count")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}

		if want, have := 1, len(m.tokens); want != have {
			t.Errorf("unexpected number of tokens: want %d, have %d", want, have)
		}

		expectedMacro := macroToken{"%{tx.count", variables.Unknown, ""}
		if want, have := m.tokens[0], expectedMacro; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}
	})

	t.Run("malformed variable", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{something_random}")
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("valid macro", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.count}")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}

		if want, have := 1, len(m.tokens); want != have {
			t.Errorf("unexpected number of tokens: want %d, have %d", want, have)
		}

		expectedMacro := macroToken{"tx.count", variables.TX, "count"}
		if want, have := m.tokens[0], expectedMacro; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}
	})

	t.Run("multi variable", func(t *testing.T) {
		m := &macro{}
		err := m.compile("%{tx.id} got %{tx.count} in this transaction")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}

		if want, have := 4, len(m.tokens); want != have {
			t.Errorf("unexpected number of tokens: want %d, have %d", want, have)
		}

		expectedMacro0 := macroToken{"tx.id", variables.TX, "id"}
		if want, have := m.tokens[0], expectedMacro0; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro1 := macroToken{" got ", variables.Unknown, ""}
		if want, have := m.tokens[1], expectedMacro1; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro2 := macroToken{"tx.count", variables.TX, "count"}
		if want, have := m.tokens[2], expectedMacro2; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}

		expectedMacro3 := macroToken{" in this transaction", variables.Unknown, ""}
		if want, have := m.tokens[3], expectedMacro3; want != have {
			t.Errorf("unexpected token: want %v, have %v", want, have)
		}
	})
}

func TestExpand(t *testing.T) {
	m := &macro{
		tokens: []macroToken{
			{"text", variables.Unknown, ""},
		},
	}

	if want, have := "text", m.Expand(nil); want != have {
		t.Errorf("unexpected expansion: want %s, have %s", want, have)
	}
}
