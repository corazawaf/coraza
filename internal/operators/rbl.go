// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.rbl

package operators

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const timeout = 500 * time.Millisecond

// Description:
// Looks up the input IP address in the specified RBL (Real-time Block List) service.
// Performs DNS lookups to check if the IP is listed. Sets TX.httpbl_msg variable with
// the response text if found. Has a 500ms timeout for DNS queries.
//
// Arguments:
// RBL hostname to query (e.g., "sbl-xbl.spamhaus.org").
//
// Returns:
// true if the IP address is found in the RBL, false otherwise or on timeout.
// As in ModSecurity, an IPv4 address is queried with its octets reversed
// (4.3.2.1.service) and any other input is used as is (domain format).
//
// Example:
// ```seclang
// # Check IP against Spamhaus blocklist
// SecRule REMOTE_ADDR "@rbl sbl-xbl.spamhaus.org" "id:183,deny,log,msg:'IP found in RBL'"
//
// # Multiple RBL checks
// SecRule REMOTE_ADDR "@rbl dnsbl.example.com" "id:184,deny"
// ```
type rbl struct {
	service  string
	resolver *net.Resolver
	timeout  time.Duration
}

var _ plugintypes.Operator = (*rbl)(nil)

func newRBL(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	return &rbl{
		service:  data,
		resolver: net.DefaultResolver,
		timeout:  timeout,
	}, nil
}

// rblResult is the outcome of one RBL lookup: listed when the name resolves,
// status holding its first TXT record when there is one.
type rblResult struct {
	listed bool
	status string
}

// https://github.com/mrichman/godnsbl
// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
// maxDNSNameLen is the longest name a DNS query can carry (RFC 1035).
const maxDNSNameLen = 253

func (o *rbl) Evaluate(tx plugintypes.TransactionState, ipAddr string) bool {
	// The input is request data: an input that cannot form a valid DNS name
	// is not worth copying, let alone resolving.
	if len(ipAddr)+1+len(o.service) > maxDNSNameLen {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	addr := rblAddress(ipAddr, o.service)
	// Buffered so the lookup goroutine can deliver its result and exit after a
	// timeout, when nobody receives any more.
	resC := make(chan rblResult, 1)
	go func() {
		resC <- o.lookup(ctx, addr)
	}()

	select {
	case res := <-resC:
		if res.status != "" {
			tx.Variables().TX().Set("httpbl_msg", []string{res.status})
			tx.CaptureField(0, res.status)
		}
		return res.listed
	case <-ctx.Done():
		return false
	}
}

// rblAddress builds the name to look up the way ModSecurity's mapIpToAddress
// does: an IPv4 address has its octets reversed, as DNS block lists expect,
// and anything else is treated as domain-format input and used as is.
func rblAddress(input, service string) string {
	if ip4 := net.ParseIP(input).To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.%s", ip4[3], ip4[2], ip4[1], ip4[0], service)
	}
	return input + "." + service
}

func (o *rbl) lookup(ctx context.Context, addr string) rblResult {
	hosts, err := o.resolver.LookupHost(ctx, addr)
	if err != nil {
		return rblResult{}
	}
	if len(hosts) == 0 {
		return rblResult{listed: true}
	}
	// The host lookup decides the listing; the TXT record is optional status
	// text, so a missing one (an error from the resolver) is not a miss.
	res := rblResult{listed: true}
	if txt, err := o.resolver.LookupTXT(ctx, addr); err == nil && len(txt) > 0 {
		res.status = txt[0]
	}
	return res
}

func init() {
	Register("rbl", newRBL)
}
