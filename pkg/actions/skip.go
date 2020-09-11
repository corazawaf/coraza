// Copyright 2020 Juan Pablo Tosso
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

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strconv"
)

//NOT IMPLEMENTED
type Skip struct {
	data int
}

func (a *Skip) Init(r *engine.Rule, data string) string {
	i, err := strconv.Atoi(data)
	if err != nil{
		return "Invalid integer value"
	}
	a.data = i
	return ""
}

func (a *Skip) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Skip = a.data
}

func (a *Skip) GetType() int{
	return engine.ACTION_TYPE_FLOW
}
