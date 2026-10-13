// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.rbl

package operators

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const timeout = 500 * time.Millisecond

// Description:
// Looks up the operand in the specified RBL (Real-time Block List) zone.
// The operand becomes the query label verbatim, so it may be an IP address
// or any other key a zone is published under, such as a SHA-1 hex digest.
// Sets TX.httpbl_msg to the zone's TXT reason when one exists. Has a 500ms
// timeout for DNS queries.
//
// Arguments:
// RBL zone to query (e.g., "pswd.rbl.imunify.com.").
//
// Returns:
// true if the operand is listed — the zone answers with a listing code
// inside 127.0.0.0/8 — false otherwise or on lookup failure
//
// Example:
// ```
// # Check the client address against a regular-order blocklist
// SecRule TX:rbl_ip "@rbl www-brute.v2.rbl.imunify.com." "id:183,deny,log,msg:'IP found in RBL'"
//
// # Check a hashed credential against a hash-keyed zone
// SecRule TX:weak_pwd "@rbl pswd.rbl.imunify.com." "id:184,deny"
// ```
type rbl struct {
	service  string
	resolver *net.Resolver
}

var _ plugintypes.Operator = (*rbl)(nil)

func newRBL(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	if data == "" {
		// Without a zone every lookup goes to the DNS root and no operand can
		// ever be listed, so the rule would load as enforcement that is inert.
		return nil, errors.New("missing RBL service hostname")
	}

	return &rbl{
		service:  data,
		resolver: net.DefaultResolver,
	}, nil
}

// https://github.com/owasp-modsecurity/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/apache2/re_operators.c (msre_op_rbl_execute)
func (o *rbl) Evaluate(tx plugintypes.TransactionState, operand string) bool {
	if operand == "" {
		tx.DebugLogger().Debug().Msg("RBL lookup skipped: empty operand")
		return false
	}

	// The lookups take the deadline through the context, so they unwind on
	// their own and no work outlives Evaluate. In a request phase they also end
	// with the transaction's context, so that a connector that has gone away does
	// not leave them waiting out the timeout.
	parent := context.Background()
	if pc, ok := tx.(interface{ PhaseContext() context.Context }); ok {
		parent = pc.PhaseContext()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	// The query name is the operand written in front of the zone, verbatim.
	// Blocklists disagree on the key form — public RFC 5782 zones expect
	// reversed IPv4 octets, while the Imunify zones queried in production
	// (rbl.imunify.com) are keyed by regular-order addresses and SHA-1
	// hashes — so the operand passes through untouched and each rule
	// supplies the key in the form its zone expects. ModSecurity sends every
	// operand that is not a bare IPv4 address the same way, and the Imunify
	// ruleset feeds all engines operands of exactly that shape. An operand
	// no zone can list — an IPv6 address, junk request data — fails the
	// lookup and is reported unlisted.
	addr := operand + "." + o.service
	// LookupIP and LookupNetIP would undo the deadline: they go through the
	// shared lookup group in net, where concurrent lookups of one name join a
	// single call that stops being cancellable as soon as it has a second
	// waiter and then outlives all of them, so a slow blocklist would pin a
	// goroutine per request.
	res, err := o.resolver.LookupHost(ctx, addr)
	if err != nil {
		logRBLLookupError(tx, addr, err)
		return false
	}
	if !anyListingCode(res) {
		tx.DebugLogger().Warn().
			Str("address", addr).
			Str("answers", strings.Join(res, " ")).
			Msg("RBL answer is not a listing code, treating operand as not listed")
		return false
	}

	// The address record alone decides that the operand is listed. The TXT
	// record only carries the human-readable reason, so a zone that publishes
	// none — or a TXT lookup that fails on its own — must not undo the
	// verdict.
	var reason string
	if txt, err := o.resolver.LookupTXT(ctx, addr); err != nil {
		// The address lookup that just succeeded proves the resolver answers,
		// so a failure here is almost always a zone with no TXT record, and it
		// costs nothing: the verdict is already settled.
		tx.DebugLogger().Debug().Err(err).Str("address", addr).Msg("RBL reason lookup failed")
	} else if len(txt) > 0 {
		reason = txt[0]
	}
	// Whatever the reason turns out to be, it has to describe this match: a
	// zone that publishes no TXT record must not leave an earlier RBL rule's
	// message standing as if it belonged here.
	if reason == "" {
		tx.Variables().TX().Remove("httpbl_msg")
	} else {
		tx.Variables().TX().Set("httpbl_msg", []string{reason})
	}
	tx.CaptureField(0, reason)
	return true
}

// anyListingCode reports whether an answer means the operand asked about is
// listed. RFC 5782 §2.1 puts a listing in 127.0.0.0/8, and zones answer in the
// top of that block, 127.255.255.0/24, to complain about the query itself — a
// public resolver, an exhausted quota — which says nothing about the operand.
// A resolver that invents an address for every name it cannot resolve answers
// outside 127.0.0.0/8 altogether. Reading either as a listing would block
// every request.
func anyListingCode(answers []string) bool {
	for _, answer := range answers {
		v4 := net.ParseIP(answer).To4()
		if v4 != nil && v4[0] == 127 && (v4[1] != 255 || v4[2] != 255) {
			return true
		}
	}
	return false
}

// logRBLLookupError reports a failed lookup at the level its cause deserves. A
// missing record is the ordinary negative answer, a timeout is the service
// being slow, and a cancelled lookup is the caller giving up, so none of them
// is logged as an engine error: an unreachable or slow RBL would otherwise
// write one error line per request.
func logRBLLookupError(tx plugintypes.TransactionState, addr string, err error) {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		tx.DebugLogger().Debug().Str("address", addr).Msg("RBL record not found")
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		tx.DebugLogger().Warn().Str("address", addr).Msg("RBL lookup timed out, treating operand as not listed")
	case errors.Is(err, context.Canceled):
		tx.DebugLogger().Debug().Str("address", addr).Msg("RBL lookup cancelled")
	default:
		tx.DebugLogger().Error().Err(err).Str("address", addr).Msg("RBL DNS lookup failed")
	}
}

func init() {
	Register("rbl", newRBL)
}
