// Copyright 2021 Juan Pablo Tosso
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

	engine "github.com/jptosso/coraza-waf"
)

var HTTP_STATUSES = []int{100, 101, 102, 103, 200,
	201, 202, 203, 200, 204, 205, 206, 207, 208,
	226, 300, 301, 302, 303, 304, 305, 306, 307,
	302, 308, 301, 400, 401, 402, 403, 404, 405,
	406, 407, 408, 409, 410, 411, 412, 413, 414,
	415, 416, 417, 418, 421, 422, 423, 424, 426,
	428, 429, 431, 451, 500, 501, 502, 503, 504,
	505, 506, 507, 508, 510, 511, 511}

type Status struct {
}

func (a *Status) Init(r *engine.Rule, b1 string) error {
	status, _ := strconv.Atoi(b1)
	for _, s := range HTTP_STATUSES {
		if status == s {
			r.Status = status
			return nil
		}
	}
	return fmt.Errorf("Invalid HTTP status")
}

func (a *Status) Evaluate(r *engine.Rule, tx *engine.Transaction) {

}

func (a *Status) GetType() int {
	return engine.ACTION_TYPE_DATA
}
