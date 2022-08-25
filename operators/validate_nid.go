// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

type validateNidFunction = func(input string) bool

type validateNid struct {
	fn validateNidFunction
	re *regexp.Regexp
}

func (o *validateNid) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2 {
		return fmt.Errorf("invalid @validateNid argument")
	}
	switch spl[0] {
	case "cl":
		o.fn = nidCl
	case "us":
		o.fn = nidUs
	default:
		return fmt.Errorf("invalid @validateNid argument")
	}
	re, err := regexp.Compile(spl[1])
	if err != nil {
		return err
	}
	o.re = re
	return nil
}

func (o *validateNid) Evaluate(tx *coraza.Transaction, value string) bool {
	matches := o.re.FindAllStringSubmatch(value, -1)

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
