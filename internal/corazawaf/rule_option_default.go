// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.multiphase_evaluation

package corazawaf

// multiphaseEvaluation indicates whether we should evaluate rules that match against variables
// ready in multiple phases in each of those phases. CRS sets the phase for many rules to the
// maximum phase of all variables, which means that earlier variables have evaluation deferred.
const multiphaseEvaluation = false
