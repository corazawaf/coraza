// Copyright 2022 coraza
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http:// www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coraza

import (
	"go.uber.org/zap"
)

type Fields map[string]interface{}

type Logger interface {
	WithField(key string, val interface{}) Logger
	WithFields(fields Fields) Logger

	Info(v ...interface{})
	Warn(v ...interface{})
	Error(v ...interface{})
	Debug(v ...interface{})
}

func NewEmptyLogger() Logger {
	return &emptyLogger{}
}

type emptyLogger struct{}

func (l *emptyLogger) WithField(_ string, _ interface{}) Logger { return l }
func (l *emptyLogger) WithFields(_ Fields) Logger               { return l }
func (l *emptyLogger) Info(_ ...interface{})                    {}
func (l *emptyLogger) Warn(_ ...interface{})                    {}
func (l *emptyLogger) Error(_ ...interface{})                   {}
func (l *emptyLogger) Debug(_ ...interface{})                   {}

func NewZapLogger(entry *zap.Logger) Logger {
	return &zapLogger{entry: entry.Sugar()}
}

type zapLogger struct {
	entry *zap.SugaredLogger
}

func (l *zapLogger) clone() *zapLogger {
	cp := *l
	return &cp
}

func (l *zapLogger) change(fields Fields) []interface{} {
	if fields == nil {
		return nil
	}

	set := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		set = append(set, k, v)
	}
	return set
}

func (l *zapLogger) WithField(key string, val interface{}) Logger {
	cl := l.clone()
	cl.entry = l.entry.With(key, val)
	return cl
}

func (l *zapLogger) WithFields(fields Fields) Logger {
	set := l.change(fields)
	cl := l.clone()
	cl.entry = l.entry.With(set...)
	return cl
}

func (l *zapLogger) Info(v ...interface{}) {
	l.entry.Info(v...)
}

func (l *zapLogger) Warn(v ...interface{}) {
	l.entry.Warn(v...)
}

func (l *zapLogger) Error(v ...interface{}) {
	l.entry.Error(v...)
}

func (l *zapLogger) Debug(v ...interface{}) {
	l.entry.Debug(v...)
}
