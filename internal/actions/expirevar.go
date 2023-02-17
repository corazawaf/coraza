// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
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

func (a *expirevarFn) Init(_ rules.RuleMetadata, data string) error {
	k, ttl, ok := strings.Cut(data, "=")
	if !ok {
		return ErrInvalidKVArguments
	}

	col, key, ok := strings.Cut(k, ".")
	if !ok {
		return errors.New("invalid arguments, expected syntax {collection}.{key}={ttl}")
	}

	ittl, err := strconv.Atoi(ttl)
	if err != nil {
		return fmt.Errorf("invalid TTL argument %q: %s", ttl, err.Error())
	}

	if ittl < int(1) {
		return fmt.Errorf("invalid TTL argument, %d must be greater than 1", ittl)
	}

	a.ttl = ittl
	a.collection = col
	a.key = key
	return nil
}

func (a *expirevarFn) Evaluate(_ rules.RuleMetadata, _ rules.TransactionState) {
	// Not supported
	// TODO(jcchavezs): Shall we log a message?
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
