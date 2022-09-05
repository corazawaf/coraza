// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

// Initializes a persistent collection and add the data to the standard collections coraza.
type initcolFn struct {
	collection string
	variable   byte
	key        string
}

func (a *initcolFn) Init(r *corazawaf.Rule, data string) error {
	kv := strings.SplitN(data, "=", 2)
	a.collection = kv[0]
	a.key = kv[1]
	a.variable = 0x0
	return nil
}

func (a *initcolFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	// tx.WAF.Logger.Error("initcol was used but it's not supported", zap.Int("rule", r.Id))
	/*
		key := tx.MacroExpansion(a.key)
		data := tx.WAF.Persistence.Get(a.variable, key)
		if data == nil {
			ts := time.Now().UnixNano()
			tss := strconv.FormatInt(ts, 10)
			tsstimeout := strconv.FormatInt(ts+(int64(tx.WAF.CollectionTimeout)*1000), 10)
			data = map[string][]string{
				"CREATE_TIME":      {tss},
				"IS_NEW":           {"1"},
				"KEY":              {key},
				"LAST_UPDATE_TIME": {tss},
				"TIMEOUT":          {tsstimeout},
				"UPDATE_COUNTER":   {"0"},
				"UPDATE_RATE":      {"0"},
			}
		}
		tx.GetCollection(a.variable).SetData(data)
		tx.PersistentCollections[a.variable] = key
	*/
}

func (a *initcolFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func initcol() corazawaf.RuleAction {
	return &initcolFn{}
}

var (
	_ corazawaf.RuleAction = &initcolFn{}
	_ ruleActionWrapper    = initcol
)
