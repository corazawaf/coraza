// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNop(t *testing.T) {
	l := Noop().(defaultLogger)
	require.Equal(t, LevelNoLog, l.level, "unexpected log level when nop")

	lwo := l.WithOutput(io.Discard).(defaultLogger)
	require.NotNil(t, lwo.factory, "unexpected logger factory")
}
