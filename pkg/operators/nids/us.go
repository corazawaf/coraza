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

import (
	"regexp"
	"strconv"
)

type NidUs struct{}

func (n *NidUs) Evaluate(nid string) bool {
	re, err := regexp.Compile(`[^\d]`)
	if err != nil {
		return false
	}
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
