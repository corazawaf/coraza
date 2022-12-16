// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateByteRange

package operators

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
)

type validateByteRange struct {
	validBytes [256]bool // array, not slice, so don't pass as-is to functions
}

var _ rules.Operator = (*validateByteRange)(nil)

func newValidateByteRange(options rules.OperatorOptions) (rules.Operator, error) {
	data := options.Arguments

	if data == "" {
		return &unconditionalMatch{}, nil
	}

	var validBytes [256]bool
	for _, br := range strings.Split(data, ",") {
		br = strings.TrimSpace(br)
		start, end, ok := strings.Cut(br, "-")

		if !ok {
			if b, err := strconv.Atoi(start); err != nil {
				return nil, err
			} else if err := validateByte(b); err != nil {
				return nil, err
			} else {
				validBytes[b] = true
			}
			continue
		}
		s, err := strconv.Atoi(start)
		if err != nil {
			return nil, err
		}
		if err := validateByte(s); err != nil {
			return nil, err
		}
		e, err := strconv.Atoi(end)
		if err != nil {
			return nil, err
		}
		if err := validateByte(e); err != nil {
			return nil, err
		}
		for i := s; i <= e; i++ {
			validBytes[i] = true
		}
	}
	return &validateByteRange{validBytes: validBytes}, nil
}

func validateByte(b int) error {
	if b < 0 || b > 255 {
		return fmt.Errorf("invalid byte %d", b)
	}
	return nil
}

func (o *validateByteRange) Evaluate(tx rules.TransactionState, data string) bool {
	if data == "" {
		return false
	}
	// we must iterate each byte from input and check if it is in the range
	// if every byte is within the range we return false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !o.validBytes[c] {
			return true
		}
	}
	return false
}

func init() {
	operators.Register("validateByteRange", newValidateByteRange)
}
