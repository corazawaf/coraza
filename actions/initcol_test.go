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

	t.Run("valid argument", func(t *testing.T) {
		initcol := initcol()
		err := initcol.Init(nil, "foo=bar")
		if err != nil {
			t.Errorf("unexpected error: %s", err.Error())
		}
	})
}
