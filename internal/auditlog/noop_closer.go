// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

var NoopCloser = noopCloser{}
