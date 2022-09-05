// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type byteRange struct {
	start byte
	end   byte
}

type validateByteRange struct {
	data []byteRange
}

func (o *validateByteRange) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	if data == "" {
		return nil
	}
	ranges := strings.Split(data, ",")
	spl := ranges
	var err error
	for _, br := range spl {
		br = strings.TrimSpace(br)
		var start, end uint64
		spl := strings.Split(br, "-")
		if len(spl) == 1 {
			start, err = strconv.ParseUint(spl[0], 10, 8)
			if err != nil {
				return err
			}
			if err := o.addRange(start, start); err != nil {
				return err
			}
			continue
		}
		start, err = strconv.ParseUint(spl[0], 10, 8)
		if err != nil {
			return err
		}
		end, err = strconv.ParseUint(spl[1], 10, 8)
		if err != nil {
			return err
		}
		if err := o.addRange(start, end); err != nil {
			return err
		}
	}
	return nil
}

func (o *validateByteRange) Evaluate(tx *corazawaf.Transaction, data string) bool {
	lenData := len(o.data)
	if lenData == 0 {
		return true
	}
	if data == "" {
		return false
	}
	// we must iterate each byte from input and check if it is in the range
	// if every byte is within the range we return false
	matched := 0
	for i := 0; i < len(data); i++ {
		c := data[i]
		for _, r := range o.data {
			if c >= r.start && c <= r.end {
				matched++
				break
			}
		}
	}
	return len(data) != matched
}

func (o *validateByteRange) addRange(start uint64, end uint64) error {
	if start > 255 {
		return fmt.Errorf("invalid byte %d", start)
	}
	if end > 255 {
		return fmt.Errorf("invalid byte %d", end)
	}
	o.data = append(o.data, byteRange{
		start: byte(start),
		end:   byte(end),
	})
	return nil
}
