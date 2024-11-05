// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"io"
	"testing"
)

func TestNop(t *testing.T) {
	l := Noop().(defaultLogger)
	if want, have := l.level, LevelNoLog; want != have {
		t.Fatalf("unexpected log level when nop")
	}

	lwo := l.WithOutput(io.Discard).(defaultLogger)
	if lwo.factory == nil {
		t.Fatalf("unexpected logger factory")
	}
}
