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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2"
)

type validateNidFunction = func(input string) bool

type validateNid struct {
	fn  validateNidFunction
	rgx string
}

func (o *validateNid) Init(data string) error {
	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2 {
		return fmt.Errorf("Invalid @validateNid argument")
	}
	switch spl[0] {
	case "cl":
		o.fn = nidCl
	case "us":
		o.fn = nidUs
	default:
		return fmt.Errorf("Invalid @validateNid argument")
	}
	o.rgx = spl[1]
	return nil
}

func (o *validateNid) Evaluate(tx *coraza.Transaction, value string) bool {
	re, _ := regexp.Compile(o.rgx)
	matches := re.FindAllStringSubmatch(value, -1)

	res := false
	for i, m := range matches {
		if i >= 10 {
			break
		}
		// should we capture more than one NID?
		if o.fn(m[0]) {
			res = true
			if tx.Capture {
				tx.CaptureField(i, m[0])
			}
		}
	}
	return res
}

func nidCl(nid string) bool {
	if len(nid) < 8 {
		return false
	}
	re := regexp.MustCompile(`[^\dk]`)
	nid = strings.ToLower(nid)
	nid = re.ReplaceAllString(nid, "")
	rut, _ := strconv.Atoi(nid[:len(nid)-1])
	dv := nid[len(nid)-1:]

	var sum = 0
	var factor = 2
	var ndv string
	for ; rut != 0; rut /= 10 {
		sum += rut % 10 * factor
		if factor == 7 {
			factor = 2
		} else {
			factor++
		}
	}

	val := 11 - (sum % 11)
	switch val {
	case 11:
		ndv = "0"
	case 10:
		ndv = "k"
	default:
		ndv = strconv.Itoa(val)
	}
	return ndv == dv
}

func nidUs(nid string) bool {
	re := regexp.MustCompile(`[^\d]`)
	nid = re.ReplaceAllString(nid, "")
	if len(nid) < 9 {
		return false
	}
	area, _ := strconv.Atoi(nid[0:3])
	group, _ := strconv.Atoi(nid[3:5])
	serial, _ := strconv.Atoi(nid[5:9])
	if area == 0 || group == 0 || serial == 0 || area >= 740 || area == 666 {
		return false
	}

	sequence := true
	equals := true
	prev, _ := strconv.Atoi(string(nid[0]))
	for i := 1; i < len(nid); i++ {
		curr, _ := strconv.Atoi(string(nid[i]))
		if prev != curr {
			equals = false
		}
		if curr != prev+1 {
			sequence = false
		}
		prev = curr
	}

	return !(sequence || equals)
}

var (
	_ coraza.RuleOperator = &validateNid{}
	_ validateNidFunction = nidCl
	_ validateNidFunction = nidUs
)
