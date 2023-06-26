// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Action Group: Non-disruptive
//
// Description:
// Initializes a named persistent collection, either by loading data from storage or by creating a new collection in memory.
// Collections are loaded into memory on-demand, when the initcol action is executed.
// A collection will be persisted only if a change was made to it in the course of transaction processing.
// See the `Persistent Storage` section for further details.
//
// Example:
// ```
// # Initiates IP address tracking, which is best done in phase 1
// SecAction "phase:1,id:116,nolog,pass,initcol:ip=%{REMOTE_ADDR}"
// ```
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
