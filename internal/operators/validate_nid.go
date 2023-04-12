// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateNid

package operators

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type validateNidFunction = func(input string) bool

type validateNid struct {
	fn validateNidFunction
	re *regexp.Regexp
}

var _ plugintypes.Operator = (*validateNid)(nil)

func newValidateNID(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	typ, expr, ok := strings.Cut(data, " ")
	if !ok {
		return nil, fmt.Errorf("invalid @validateNid argument")
	}
	var fn validateNidFunction
	switch typ {
	case "cl":
		fn = nidCl
	case "us":
		fn = nidUs
	default:
		return nil, fmt.Errorf("invalid @validateNid argument")
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return &validateNid{fn: fn, re: re}, nil
}

func (o *validateNid) Evaluate(tx plugintypes.TransactionState, value string) bool {
	matches := o.re.FindAllStringSubmatch(value, 11)

	res := false
	for i, m := range matches {
		if i >= 10 {
			break
		}
		// should we capture more than one NID?
		if o.fn(m[0]) {
			res = true
			tx.CaptureField(i, m[0])
		}
	}
	return res
}

var nonDigitOrK = regexp.MustCompile(`[^\dk]`)

func nidCl(nid string) bool {
	if len(nid) < 8 {
		return false
	}
	nid = strings.ToLower(nid)
	nid = nonDigitOrK.ReplaceAllString(nid, "")
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

	val := sum % 11
	switch val {
	case 0:
		ndv = "0"
	case 1:
		ndv = "k"
	default:
		ndv = strconv.Itoa(11 - val)
	}
	return ndv == dv
}

var nonDigit = regexp.MustCompile(`[^\d]`)

func nidUs(nid string) bool {
	nid = nonDigit.ReplaceAllString(nid, "")
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
	prev := digitToInt(nid[0])
	for i := 1; i < len(nid); i++ {
		curr := digitToInt(nid[i])
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

func digitToInt(d byte) int {
	return int(d - '0')
}

var (
	_ plugintypes.Operator = &validateNid{}
	_ validateNidFunction  = nidCl
	_ validateNidFunction  = nidUs
)

func init() {
	Register("validateNid", newValidateNID)
}
