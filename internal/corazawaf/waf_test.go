// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"context"
	"io"
	"os"
	"testing"
)

func TestNewTransaction(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	waf.ResponseBodyAccess = true
	waf.RequestBodyLimit = 1044
	tx := waf.NewTransaction(context.Background())
	if !tx.RequestBodyAccess {
		t.Error("Request body access not enabled")
	}
	if !tx.ResponseBodyAccess {
		t.Error("Response body access not enabled")
	}
	if tx.RequestBodyLimit != 1044 {
		t.Error("Request body limit not set")
	}
}

func TestSetDebugLogPath(t *testing.T) {
	waf := NewWAF()

	testCases := []struct {
		path   string
		writer io.Writer
	}{
		{
			path:   "/dev/stdout",
			writer: os.Stdout,
		},
		{
			path:   "/dev/stderr",
			writer: os.Stderr,
		},
	}

	for _, tCase := range testCases {
		t.Run(tCase.path, func(t *testing.T) {
			err := waf.SetDebugLogPath(tCase.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			l := waf.Logger.(*stdDebugLogger)
			if want, have := tCase.writer, l.logger.Writer(); want != have {
				t.Error("unexpected logger writer")
			}
			_ = waf.SetDebugLogPath("")
		})
	}
}
