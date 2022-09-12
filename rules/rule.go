// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package rules

type Rule interface {
	IDString() int
	ParentIDString() int
	Status() int
}
