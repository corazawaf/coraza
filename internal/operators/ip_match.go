// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatch

package operators

import (
	"net"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs fast IPv4 or IPv6 address matching with support for CIDR notation.
// Can match individual IPs or IP ranges. Automatically adds appropriate subnet masks
// (/32 for IPv4, /128 for IPv6) when not specified.
//
// Arguments:
// Comma-separated list of IP addresses with optional CIDR blocks (e.g., "192.168.1.0/24, 10.0.0.1").
//
// Returns:
// true if the input IP address matches any of the provided IPs or ranges, false otherwise
//
// Example:
// ```
// # Block specific IPs and ranges
// SecRule REMOTE_ADDR "@ipMatch 192.168.1.100,192.168.1.50,10.10.50.0/24" "id:160,deny,log"
//
// # Allow internal network
// SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,172.16.0.0/12" "id:161,pass"
// ```
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
