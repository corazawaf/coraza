// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"
)

func TestMacro(t *testing.T) {
	tx := makeTransaction()
	tx.Variables.TX.Set("some", []string{"secretly"})
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
	if !macro.IsExpandable() || len(macro.tokens) != 4 || macro.Expand(tx) != "some complex text secretly wrapped in macro secretly" {
		t.Errorf("failed to parse replacements %v", macro.tokens)
	}
}
