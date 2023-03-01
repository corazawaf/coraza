package loggers

import (
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
)

type defaultEvent struct {
	level  LogLevel
	logger *log.Logger
	entry  []byte
}

var boolMap = map[bool]string{
	true:  "true",
	false: "false",
}

func (e *defaultEvent) Msg(msg string) {
	if len(msg) == 0 {
		return
	}

	s := strings.Builder{}
	s.WriteString("[")
	s.WriteString(e.level.String())
	s.WriteString("] ")
	s.WriteString(msg)
	s.Write(e.entry)

	e.logger.Println(s.String())
}

func (e *defaultEvent) Str(key, val string) Event {
	e.entry = append(e.entry, ' ')
	e.entry = append(e.entry, key...)
	e.entry = append(e.entry, '=')
	e.entry = append(e.entry, val...)
	return e
}

func (e *defaultEvent) Err(err error) Event {
	if err == nil {
		return e
	}

	e.entry = append(e.entry, " error="...)
	e.entry = append(e.entry, err.Error()...)
	return e
}

func (e *defaultEvent) Bool(key string, b bool) Event {
	e.entry = append(e.entry, ' ')
	e.entry = append(e.entry, key...)
	e.entry = append(e.entry, '=')
	e.entry = append(e.entry, boolMap[b]...)
	return e
}

func (e *defaultEvent) Int(key string, i int) Event {
	e.entry = append(e.entry, ' ')
	e.entry = append(e.entry, key...)
	e.entry = append(e.entry, '=')
	e.entry = append(e.entry, strconv.Itoa(i)...)
	return e
}

func (e *defaultEvent) Uint(key string, i uint) Event {
	e.entry = append(e.entry, ' ')
	e.entry = append(e.entry, key...)
	e.entry = append(e.entry, '=')
	e.entry = append(e.entry, strconv.Itoa(int(i))...)
	return e
}

func (e *defaultEvent) Stringer(key string, val fmt.Stringer) Event {
	e.entry = append(e.entry, ' ')
	e.entry = append(e.entry, key...)
	e.entry = append(e.entry, '=')
	e.entry = append(e.entry, val.String()...)
	return e
}

type defaultLogger struct {
	*log.Logger
	level LogLevel
}

func (l defaultLogger) WithOutput(w io.Writer) DebugLogger {
	if l.Logger == nil {
		return defaultLogger{
			Logger: log.New(w, "", log.LstdFlags),
			level:  l.level,
		}
	}

	return defaultLogger{
		Logger: log.New(w, l.Logger.Prefix(), l.Logger.Flags()),
		level:  l.level,
	}
}

func (l defaultLogger) WithLevel(lvl LogLevel) DebugLogger {
	return defaultLogger{Logger: l.Logger, level: lvl}
}

func (l defaultLogger) Trace() Event {
	if l.level < LogLevelTrace || l.Logger == nil {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Debug() Event {
	if l.level < LogLevelDebug || l.Logger == nil {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Info() Event {
	if l.level < LogLevelInfo || l.Logger == nil {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Warn() Event {
	if l.level < LogLevelWarn || l.Logger == nil {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Error() Event {
	if l.level < LogLevelError || l.Logger == nil {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func Default() DebugLogger {
	return defaultLogger{
		Logger: log.Default(),
		level:  LogLevelInfo,
	}
}
