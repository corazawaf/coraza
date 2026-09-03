// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.rule.multiphase_evaluation

package coreruleset

import "github.com/coreruleset/go-ftw/v2/config"

func loadMultiphaseOverrides(_ *config.FTWConfiguration) error { return nil }
