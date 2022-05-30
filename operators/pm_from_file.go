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

package operators

import (
	"bufio"
	"strings"

	"github.com/cloudflare/ahocorasick"
	"github.com/corazawaf/coraza/v2"
)

type pmFromFile struct {
	pm *pm
}

func (o *pmFromFile) Init(data string) error {
	lines := []string{}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		lines = append(lines, strings.ToLower(l))
	}
	o.pm = &pm{
		dict:    lines,
		matcher: ahocorasick.NewStringMatcher(lines),
	}
	return nil
}

func (o *pmFromFile) Evaluate(tx *coraza.Transaction, value string) bool {
	return o.pm.Evaluate(tx, value)
}
