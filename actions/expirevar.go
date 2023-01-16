// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

type expirevarFn struct {
	collection string
	ttl        int
	key        string
}

func (a *expirevarFn) Init(r rules.RuleMetadata, data string) error {
	v, ttl, _ := strings.Cut(data, "=")
	col, key, ok := strings.Cut(v, ".")
	if !ok {
		return fmt.Errorf("expirevar must contain key and value (syntax expirevar:key=value)")
	}
	a.ttl, _ = strconv.Atoi(ttl)
	a.collection = col
	a.key = key
	return nil
}

func (a *expirevarFn) Evaluate(r rules.RuleMetadata, tx rules.TransactionState) {
	// Not supported
	// tx.WAF.Logger.Error("Expirevar was used but it's not supported", zap.Int("rule", r.Id))
}

func (a *expirevarFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func expirevar() rules.Action {
	return &expirevarFn{}
}

var (
	_ rules.Action      = &expirevarFn{}
	_ ruleActionWrapper = expirevar
)
