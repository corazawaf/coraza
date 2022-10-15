// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/rules"
)

func TestValidateByteRangeCase4(t *testing.T) {
	ranges := "0-255"
	op := &validateByteRange{}
	opts := rules.OperatorOptions{
		Arguments: ranges,
	}
	if err := op.Init(opts); err != nil {
		t.Error("Cannot init byte range operator")
	}
	tx := getTransaction()
	if op.Evaluate(tx, "\u00d0\u0090") {
		t.Error("Invalid byte between ranges (negative)", []byte("\u00d0\u0090"))
	}
}

func TestValidateByteRangeCase5(t *testing.T) {
	ranges := "9,10,13,32-126,128-255"
	op := &validateByteRange{}
	opts := rules.OperatorOptions{
		Arguments: ranges,
	}
	if err := op.Init(opts); err != nil {
		t.Error("Cannot init byte range operator")
	}
	if len(op.data) != 5 || op.data[0].start != 9 || op.data[1].start != 10 || op.data[2].start != 13 || op.data[3].start != 32 ||
		op.data[3].end != 126 || op.data[4].start != 128 || op.data[4].end != 255 {
		t.Error("Invalid range length", len(op.data))
	}
	if op.Evaluate(nil, "/\ufffdindex.html?test=test1") {
		t.Error("Invalid byte between ranges (negative)", []byte("/\ufffdindex.html?test=test1"))
	}
}

func getTransaction() *corazawaf.Transaction {
	waf := corazawaf.NewWAF()
	return waf.NewTransaction()
}

func BenchmarkValidateByteRange(b *testing.B) {
	ranges := "9,10,13,32-126,128-255"
	op := &validateByteRange{}
	opts := rules.OperatorOptions{
		Arguments: ranges,
	}
	if err := op.Init(opts); err != nil {
		b.Error("Cannot init byte range operator")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		op.Evaluate(nil, "/\ufffdindex.html?test=test1")
	}
}
