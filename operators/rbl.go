// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package operators

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

const timeout = 500 * time.Millisecond

type rbl struct {
	service  string
	resolver *net.Resolver
}

func (o *rbl) Init(options corazawaf.RuleOperatorOptions) error {
	data := options.Arguments

	o.service = data
	o.resolver = net.DefaultResolver
	// TODO validate hostname
	return nil
}

// https://github.com/mrichman/godnsbl
// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *rbl) Evaluate(tx *corazawaf.Transaction, ipAddr string) bool {
	// TODO validate address
	resC := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
	}()

	addr := fmt.Sprintf("%s.%s", ipAddr, o.service)
	captures := []string{}
	go func(ctx context.Context) {
		defer func() {
			close(resC)
		}()
		res, err := o.resolver.LookupHost(ctx, addr)

		if err != nil {
			resC <- false
			return
		}
		// var status string
		if len(res) > 0 {
			txt, err := o.resolver.LookupTXT(ctx, addr)
			if err != nil {
				resC <- false
				return
			}

			if len(txt) > 0 {
				status := txt[0]
				captures = append(captures, status)
				tx.Variables.TX.Set("httpbl_msg", []string{status})
			}
		}

		resC <- true
	}(ctx)

	select {
	case res := <-resC:
		if res && len(captures) > 0 {
			tx.CaptureField(0, captures[0])
		}
		return res
	case <-time.After(timeout):
		return false
	}
}
