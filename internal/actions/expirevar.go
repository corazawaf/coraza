// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Action Group: Non-disruptive
//
// Description:
// Configures a collection variable to expire after the given time period (in seconds).
// You should use the `expirevar` with `setvar` action to keep the intended expiration time.
// The expire time will be reset if they are used on their own (perhaps in a SecAction directive).
//
// Example:
// ```
//
//	SecRule REQUEST_COOKIES:JSESSIONID "!^$" "nolog,phase:1,id:114,pass,setsid:%{REQUEST_COOKIES:JSESSIONID}"
//
//	SecRule REQUEST_URI "^/cgi-bin/script\.pl" "phase:2,id:115,t:none,t:lowercase,t:normalizePath,log,allow,\
//		setvar:session.suspicious=1,expirevar:session.suspicious=3600,phase:1"
//
// ```

type expirevarFn struct {
	key        macro.Macro
	ttl        int
	collection variables.RuleVariable
}

func (a *expirevarFn) Init(_ plugintypes.RuleMetadata, data string) error {
	if len(data) == 0 {
		return errors.New("expirevar: missing arguments")
	}

	// Split the input "variable=ttl" (e.g., "ip.request_count=60")
	key, ttlStr, ttlOk := strings.Cut(data, "=")
	colKey, colVal, colOk := strings.Cut(key, ".")

	// Ensure the collection is one of the editable ones
	available := []string{"TX", "USER", "GLOBAL", "RESOURCE", "SESSION", "IP"}
	if !utils.InSlice(strings.ToUpper(colKey), available) {
		return errors.New("expirevar: invalid collection, available collections are: " + strings.Join(available, ", "))
	}
	if strings.TrimSpace(colVal) == "" {
		return errors.New("expirevar: invalid variable format, expected syntax COLLECTION.{key}=ttl")
	}

	// Parse the collection and the variable name
	var err error
	a.collection, err = variables.Parse(colKey)
	if err != nil {
		return err
	}
	if colOk {
		a.key, err = macro.NewMacro(colVal)
		if err != nil {
			return err
		}
	}

	// Parse the TTL value
	if !ttlOk {
		return errors.New("expirevar: missing TTL value")
	}
	ttlSeconds, err := strconv.Atoi(strings.TrimSpace(ttlStr))
	if err != nil || ttlSeconds <= 0 {
		return errors.New("expirevar: invalid TTL, must be a positive integer")
	}
	a.ttl = ttlSeconds
	return nil
}

func (a *expirevarFn) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	// TODO: TX support
	// It has collection.Map interface and will not be converted to collection.Persistent
	col, ok := tx.Collection(a.collection).(collection.Persistent)
	if !ok {
		tx.DebugLogger().Error().Msg("collection in expirevar is not editable")
		return
	}
	// update the TTL
	key := a.key.Expand(tx)
	col.SetTTL(key, a.ttl)
}

func (a *expirevarFn) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func expirevar() plugintypes.Action {
	return &expirevarFn{}
}

var (
	_ plugintypes.Action = &expirevarFn{}
	_ ruleActionWrapper  = expirevar
)
