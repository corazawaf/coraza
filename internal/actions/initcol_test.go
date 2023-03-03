// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import "testing"

func TestInitcolInit(t *testing.T) {
	t.Run("invalid argument", func(t *testing.T) {
		initcol := initcol()
		err := initcol.Init(nil, "foo")
		if err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("passing argument", func(t *testing.T) {
		initcol := initcol()
		err := initcol.Init(nil, "foo=bar")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}
	})
}
