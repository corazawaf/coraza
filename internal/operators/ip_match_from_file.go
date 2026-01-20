// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatchFromFile

package operators

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs IPv4/IPv6 address matching like @ipMatch but loads IP addresses from file(s).
// Supports CIDR notation. Lines starting with # are treated as comments and empty lines are ignored.
// Also available as @ipMatchF (shorthand alias).
//
// Arguments:
// File path containing IP addresses and CIDR blocks, one per line.
//
// Returns:
// true if the input IP address matches any IP or range from the file(s), false otherwise
//
// Example:
// ```
// # Block IPs from denylist file
// SecRule REMOTE_ADDR "@ipMatchFromFile /etc/waf/blocked-ips.txt" "id:162,deny,log"
//
// # Using shorthand alias
// SecRule REMOTE_ADDR "@ipMatchF suspicious-ips.txt" "id:163,deny"
// ```
func newIPMatchFromFile(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	path := options.Arguments

	data, err := loadFromFile(path, options.Path, options.Root)
	if err != nil {
		return nil, err
	}

	dataParsed := strings.Builder{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		l = strings.TrimSpace(l)
		if len(l) == 0 {
			continue
		}
		if l[0] == '#' {
			continue
		}
		dataParsed.WriteString(",")
		dataParsed.WriteString(l)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: dataParsed.String(),
	}
	return newIPMatch(opts)
}

func init() {
	Register("ipMatchFromFile", newIPMatchFromFile)
	Register("ipMatchF", newIPMatchFromFile)
}
