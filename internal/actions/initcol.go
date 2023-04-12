// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Initializes a persistent collection and add the data to the standard collections coraza.
type initcolFn struct {
	collection string
	variable   byte
	key        string
}

func (a *initcolFn) Init(_ plugintypes.RuleMetadata, data string) error {
	col, key, ok := strings.Cut(data, "=")
	if !ok {
		return ErrInvalidKVArguments
	}

	a.collection = col
	a.key = key
	a.variable = 0x0
	return nil
}

func (a *initcolFn) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) {
	// tx.DebugLogger().Error().Msg("initcol was used but it's not supported", zap.Int("rule", r.Id))
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

func (a *initcolFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func initcol() plugintypes.Action {
	return &initcolFn{}
}

var (
	_ plugintypes.Action = &initcolFn{}
	_ ruleActionWrapper  = initcol
)
