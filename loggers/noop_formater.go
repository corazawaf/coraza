// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Currently only used with TinyGo
//go:build tinygo
// +build tinygo

package loggers

func noopFormater(al *AuditLog) ([]byte, error) {
	return nil, nil
}
