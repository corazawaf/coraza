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
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2"
)

type validateByteRange struct {
	data [][]byte
}

func (o *validateByteRange) Init(data string) error {
	o.data = [][]byte{}
	if data == "" {
		return nil
	}
	ranges := strings.Split(data, ",")
	spl := ranges
	var err error
	for _, br := range spl {
		br = strings.TrimSpace(br)
		start := 0
		end := 0
		spl := strings.Split(br, "-")
		if len(spl) == 1 {
			start, err = strconv.Atoi(spl[0])
			if err != nil {
				return err
			}
			if err := o.addRange(start, start); err != nil {
				return err
			}
			continue
		}
		start, err = strconv.Atoi(spl[0])
		if err != nil {
			return err
		}
		end, err = strconv.Atoi(spl[1])
		if err != nil {
			return err
		}
		if err := o.addRange(start, end); err != nil {
			return err
		}
	}
	return nil
}

func (o *validateByteRange) Evaluate(tx *coraza.Transaction, data string) bool {
	lenData := len(o.data)
	if lenData == 0 {
		return true
	}
	if data == "" && lenData > 0 {
		return false
	}
	input := []byte(data)
	// we must iterate each byte from input and check if it is in the range
	// if every byte is within the range we return false
	matched := 0
	for _, c := range input {
		for _, r := range o.data {
			if c >= r[0] && c <= r[1] {
				matched++
				break
			}
		}
	}
	return len(input) != matched
}

func (o *validateByteRange) addRange(start int, end int) error {
	if (start < 0) || (start > 255) {
		return fmt.Errorf("invalid byte %d", start)
	}
	if (end < 0) || (end > 255) {
		return fmt.Errorf("invalid byte %d", end)
	}
	o.data = append(o.data, []byte{byte(start), byte(end)})
	return nil
}
