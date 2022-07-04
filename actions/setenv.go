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
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	"go.uber.org/zap"
)

type setenvFn struct {
	key   string
	value coraza.Macro
}

func (a *setenvFn) Init(r *coraza.Rule, data string) error {
	spl := strings.SplitN(data, "=", 2)
	if len(spl) != 2 {
		return fmt.Errorf("invalid key value for setvar")
	}
	a.key = spl[0]
	macro, err := coraza.NewMacro(spl[1])
	if err != nil {
		return err
	}
	a.value = *macro
	return nil
}

func (a *setenvFn) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	v := a.value.Expand(tx)
	// set env variable
	if err := os.Setenv(a.key, v); err != nil {
		tx.Waf.Logger.Error("Error setting env variable", zap.Error(err))
	}
	// TODO is this ok?
	tx.GetCollection(variables.Env).Set(a.key, []string{v})

}

func (a *setenvFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func setenv() coraza.RuleAction {
	return &setenvFn{}
}

var (
	_ coraza.RuleAction = &setenvFn{}
	_ ruleActionWrapper = setenv
)
