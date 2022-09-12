// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules

type Rule interface {
	GetID() int
	GetParentID() int
	Status() int
}
