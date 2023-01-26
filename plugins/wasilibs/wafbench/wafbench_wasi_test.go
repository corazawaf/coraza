// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !wasilibs_bench_default

package wafbench

import "github.com/corazawaf/coraza/v3/plugins/wasilibs"

func init() {
	wasilibs.Register()
}
