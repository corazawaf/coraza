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

package operators

import (
	"regexp"
	"strings"

	engine "github.com/jptosso/coraza-waf/v2"
)

type PmFromFile struct {
	pm *Pm
}

func (o *PmFromFile) Init(data string) error {
	// Split the data by LF or CRLF
	re := regexp.MustCompile(`\r?\n`)
	m := re.Split(data, -1)
	lines := []string{}
	for _, m := range m {
		if len(m) == 0 || m[0] == '#' {
			continue
		}
		lines = append(lines, m)
	}
	o.pm = &Pm{}
	return o.pm.Init(strings.Join(lines, " "))
}

func (o *PmFromFile) Evaluate(tx *engine.Transaction, value string) bool {
	return o.pm.Evaluate(tx, value)
}
