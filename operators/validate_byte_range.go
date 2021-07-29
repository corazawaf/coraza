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
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	engine "github.com/jptosso/coraza-waf"
)

type ValidateByteRange struct {
	re *regexp.Regexp
}

func (o *ValidateByteRange) Init(data string) error {
	ranges := strings.Split(data, ",")
	spl := ranges
	rega := []string{}
	for _, br := range spl {
		br = strings.Trim(br, " ")
		b1 := 0
		b2 := 0
		if strings.Contains(br, "-") {
			spl = strings.SplitN(br, "-", 2)
			b1, _ = strconv.Atoi(spl[0])
			b2, _ = strconv.Atoi(spl[1])
		} else {
			b1, _ := strconv.Atoi(br)
			b2 = b1
		}
		b1h := hex.EncodeToString([]byte{byte(b1)})
		b2h := hex.EncodeToString([]byte{byte(b2)})
		rega = append(rega, fmt.Sprintf("[\\x%s-\\x%s]", b1h, b2h))
	}
	rege := strings.Join(rega, "|")
	//fmt.Println(rege)
	o.re = regexp.MustCompile(rege)
	return nil
}

func (o *ValidateByteRange) Evaluate(tx *engine.Transaction, data string) bool {
	data = o.re.ReplaceAllString(data, "")
	//fmt.Println("DEBUG: ", data, len(data))
	//fmt.Printf("%s: %d\n", data, len(data))
	return len(data) > 0
}
