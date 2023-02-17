package testing

import (
	"io"
	"testing"

	"github.com/corazawaf/coraza/v3/loggers"
)

type debugLogger struct {
	t *testing.T
}

func (l debugLogger) Info(message string, args ...interface{}) { l.t.Logf(message, args...) }

func (l debugLogger) Warn(message string, args ...interface{}) { l.t.Logf(message, args...) }

func (l debugLogger) Error(message string, args ...interface{}) { l.t.Logf(message, args...) }

func (l debugLogger) Debug(message string, args ...interface{}) { l.t.Logf(message, args...) }

func (l debugLogger) Trace(message string, args ...interface{}) { l.t.Logf(message, args...) }

func (l debugLogger) SetLevel(level loggers.LogLevel) {
	l.t.Logf("Setting level to %q", level.String())
}

func (l debugLogger) SetOutput(w io.WriteCloser) {
	l.t.Log("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
}
