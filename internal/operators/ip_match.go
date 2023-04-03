// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatch

package operators

import (
	"net"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type ipMatch struct {
	subnets []net.IPNet
}

var _ plugintypes.Operator = (*ipMatch)(nil)

func newIPMatch(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	var subnets []net.IPNet
	for _, sb := range strings.Split(data, ",") {
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
		subnets = append(subnets, *subnet)
	}
	return &ipMatch{subnets: subnets}, nil
}

func (o *ipMatch) Evaluate(tx plugintypes.TransactionState, value string) bool {
	ip := net.ParseIP(value)
	for _, subnet := range o.subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func init() {
	Register("ipMatch", newIPMatch)
}
