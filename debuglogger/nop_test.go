// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import (
	"io"
	"testing"
)

func TestNop(t *testing.T) {
	l := Nop().(defaultLogger)
	if want, have := l.level, LogLevelNoLog; want != have {
		t.Fatalf("unexpected log level when nop")
	}

	lwo := l.WithOutput(io.Discard).(defaultLogger)
	if lwo.factory == nil {
		t.Fatalf("unexpected logger factory")
	}
}
