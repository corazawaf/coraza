// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation

package coreruleset

import "github.com/coreruleset/go-ftw/v2/config"

// Merges multiphase-specific overrides from .ftw-multiphase.yml into the main FTW configuration.
// This allows to have different expectations for tests that only fail in multiphase evaluation,
// without affecting non-multiphase test runs.
func loadMultiphaseOverrides(cfg *config.FTWConfiguration) error {
	multiphaseIgnoreConfig, err := config.NewConfigFromFile(".ftw-multiphase.yml")
	if err != nil {
		return err
	}
	for k, v := range multiphaseIgnoreConfig.TestOverride.Ignore {
		cfg.TestOverride.Ignore[k] = v
	}
	return nil
}
