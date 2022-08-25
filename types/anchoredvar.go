// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

// AnchoredVar stores the case preserved Original name and value
// of the variable
type AnchoredVar struct {
	// Key sensitive name
	Name  string
	Value string
}
