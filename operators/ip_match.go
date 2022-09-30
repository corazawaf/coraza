// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"net"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

type ipMatch struct {
	subnets []*net.IPNet
}

var _ rules.Operator = (*ipMatch)(nil)

func (o *ipMatch) Init(options rules.OperatorOptions) error {
	data := options.Arguments

	o.subnets = []*net.IPNet{}
	subnets := strings.Split(data, ",")
	for _, sb := range subnets {
		sb = strings.TrimSpace(sb)
		if sb == "" {
			continue
		}
		if strings.Contains(sb, ":") && !strings.Contains(sb, "/") {
			// ipv6
			sb += "/128"
		} else if strings.Contains(sb, ".") && !strings.Contains(sb, "/") {
			// ipv4
			sb += "/32"
		}
		_, subnet, err := net.ParseCIDR(sb)
		if err != nil {
			continue
		}
		o.subnets = append(o.subnets, subnet)
	}
	return nil
}

func (o *ipMatch) Evaluate(tx rules.TransactionState, value string) bool {
	ip := net.ParseIP(value)
	for _, subnet := range o.subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
