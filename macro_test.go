package coraza

import (
	"testing"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

func TestMacro(t *testing.T) {
	tx := makeTransaction()
	tx.GetCollection(variables.TX).Set("some", []string{"secretly"})
	macro, err := NewMacro("%{unique_id}")
	if err != nil {
		t.Error(err)
	}
	if macro.Expand(tx) != tx.ID {
		t.Errorf("%s != %s", macro.Expand(tx), tx.ID)
	}
	macro, err = NewMacro("some complex text %{tx.some} wrapped in macro")
	if err != nil {
		t.Error(err)
	}
	if macro.Expand(tx) != "some complex text secretly wrapped in macro" {
		t.Errorf("failed to expand macro, got %s\n%v", macro.Expand(tx), macro.tokens)
	}

	macro, err = NewMacro("some complex text %{tx.some} wrapped in macro %{tx.some}")
	if err != nil {
		t.Error(err)
		return
	}
	if len(macro.tokens) != 4 || macro.Expand(tx) != "some complex text secretly wrapped in macro secretly" {
		t.Errorf("failed to parse replacements %v", macro.tokens)
	}
}
