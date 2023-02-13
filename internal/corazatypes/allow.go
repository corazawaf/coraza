// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazatypes

// AllowType represents the values that the allow disruptive action can take
type AllowType int

const (
	AllowTypeUnset AllowType = iota
	AllowTypeAll
	AllowTypePhase
	AllowTypeRequest
)
