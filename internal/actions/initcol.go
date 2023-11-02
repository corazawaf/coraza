// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types/variables"
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
	collection variables.RuleVariable
	key        macro.Macro
}

func (a *initcolFn) Init(_ plugintypes.RuleMetadata, data string) error {
	col, key, ok := strings.Cut(data, "=")
	if !ok {
		return ErrInvalidKVArguments
	}

	c, err := variables.Parse(col)
	if err != nil {
		return fmt.Errorf("initcol: collection %s is not valid", col)
	}
	// we validate if this is a persistent collection
	persistent := []string{"USER", "SESSION", "IP", "RESOURCE", "GLOBAL"}
	if !utils.InSlice(c.Name(), persistent) {
		return fmt.Errorf("initcol: collection %s is not persistent", c.Name())
	}
	a.collection = c
	mkey, err := macro.NewMacro(key)
	if err != nil {
		return err
	}
	a.key = mkey
	return nil
}

func (a *initcolFn) Evaluate(_ plugintypes.RuleMetadata, txs plugintypes.TransactionState) {
	col := txs.Collection(a.collection)
	key := a.key.Expand(txs)
	txs.DebugLogger().Debug().Str("collection", a.collection.Name()).Str("key", key).Msg("initcol: initializing collection")
	c, ok := col.(*collections.Persistent)
	if !ok {
		txs.DebugLogger().Error().Str("collection", a.collection.Name()).Msg("initcol: collection is not a persistent collection")
		return
	}
	c.Init(key)
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
