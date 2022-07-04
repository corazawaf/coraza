// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package actions

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type expirevarFn struct {
	collection string
	ttl        int
	key        string
}

func (a *expirevarFn) Init(r *coraza.Rule, data string) error {
	spl := strings.SplitN(data, "=", 2)
	a.ttl, _ = strconv.Atoi(spl[1])
	spl = strings.SplitN(spl[0], ".", 2)
	if len(spl) != 2 {
		return fmt.Errorf("expirevar must contain key and value (syntax expirevar:key=value)")
	}
	a.collection = spl[0]
	a.key = spl[1]
	return nil
}

func (a *expirevarFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	// Not supported
	// tx.Waf.Logger.Error("Expirevar was used but it's not supported", zap.Int("rule", r.Id))
}

func (a *expirevarFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func expirevar() coraza.RuleAction {
	return &expirevarFn{}
}

var (
	_ coraza.RuleAction = &expirevarFn{}
	_ ruleActionWrapper = expirevar
)
