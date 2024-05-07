// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazarules

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/types"
)

const noID = 0

// RuleMetadata is used to store rule metadata
// that can be used across packages
type RuleMetadata struct {
	ID_          int
	File_        string
	Line_        int
	Rev_         string
	Severity_    types.RuleSeverity
	Version_     string
	Tags_        []string
	Maturity_    int
	Accuracy_    int
	Operator_    string
	Phase_       types.RulePhase
	Raw_         string
	SecMark_     string
	cachedStrID_ string
	// Contains the Id of the parent rule if you are inside
	// a chain. Otherwise, it will be 0
	ParentID_ int
}

func (r *RuleMetadata) ID() int {
	return r.ID_
}

func (r *RuleMetadata) File() string {
	return r.File_
}

func (r *RuleMetadata) Line() int {
	return r.Line_
}

func (r *RuleMetadata) Revision() string {
	return r.Rev_
}

func (r *RuleMetadata) Severity() types.RuleSeverity {
	return r.Severity_
}

func (r *RuleMetadata) Version() string {
	return r.Version_
}

func (r *RuleMetadata) Tags() []string {
	return r.Tags_
}

func (r *RuleMetadata) Maturity() int {
	return r.Maturity_
}

func (r *RuleMetadata) Accuracy() int {
	return r.Accuracy_
}

func (r *RuleMetadata) Operator() string {
	return r.Operator_
}

func (r *RuleMetadata) Phase() types.RulePhase {
	return r.Phase_
}

func (r *RuleMetadata) Raw() string {
	return r.Raw_
}

func (r *RuleMetadata) SecMark() string {
	return r.SecMark_
}

func (r *RuleMetadata) StrID() string {
	if r.cachedStrID_ == "" {
		rid := r.ID_
		if rid == noID {
			rid = r.ParentID_
		}
		r.cachedStrID_ = strconv.Itoa(rid)
	}
	return r.cachedStrID_
}
