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

package nids

import(
	"regexp"
	"strings"
	"strconv"
)

type NidCl struct{}

func (n *NidCl) Evaluate(nid string) bool{
	if len(nid) < 8{
		return false
	}
	re, err := regexp.Compile(`[^\dk]`)
	if err != nil {
		return false
	}	
	nid = strings.ToLower(nid)
	nid = re.ReplaceAllString(nid, "")
	rut, _ := strconv.Atoi(nid[:len(nid)-1])
	dv := nid[len(nid)-1:len(nid)]

	var sum = 0
	var factor = 2
	var ndv = "0"
	for ; rut != 0; rut /= 10 {
		sum += rut % 10 * factor
		if factor == 7 {
			factor = 2
		} else {
			factor++
		}
	}

	if val := 11 - (sum %11) ; val == 11 {
		ndv = "0"
	} else if val == 10 {
		ndv = "k"
	} else {
		ndv = strconv.Itoa(val)
	}
	return ndv == dv
}