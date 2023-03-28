// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/internal/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

func TestGetOperator(t *testing.T) {
	t.Run("get existing operator", func(t *testing.T) {
		operator := func(options rules.OperatorOptions) (rules.Operator, error) {
			return nil, nil
		}

		plugins.RegisterOperator("custom_operator", operator)
		_, err := operators.Get("custom_operator", rules.OperatorOptions{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
