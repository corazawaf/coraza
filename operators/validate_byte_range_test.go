// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operators

import (
	"testing"

	engine "github.com/corazawaf/coraza/v2"
	"github.com/stretchr/testify/require"
)

func TestValidateByteRangeCase4(t *testing.T) {
	ranges := "0-255"
	op := &validateByteRange{}
	err := op.Init(ranges)
	require.NoError(t, err, "cannot init byte range operator")

	tx := getTransaction()
	require.False(t, op.Evaluate(tx, "\u00d0\u0090"), "invalid byte between ranges (negative)", []byte("\u00d0\u0090"))
}

func TestValidateByteRangeCase5(t *testing.T) {
	ranges := "9,10,13,32-126,128-255"
	op := &validateByteRange{}

	err := op.Init(ranges)
	require.NoError(t, err, "Cannot init byte range operator")

	require.Len(t, op.data, 5)
	require.Equal(t, uint8(9), op.data[0].start, "invalid range length")
	require.Equal(t, uint8(10), op.data[1].start, "invalid range length")
	require.Equal(t, uint8(13), op.data[2].start, "invalid range length")
	require.Equal(t, uint8(32), op.data[3].start, "invalid range length")
	require.Equal(t, uint8(126), op.data[3].end, "invalid range length")
	require.Equal(t, uint8(128), op.data[4].start, "invalid range length")
	require.Equal(t, uint8(255), op.data[4].end, "invalid range length")

	require.False(t, op.Evaluate(nil, "/\ufffdindex.html?test=test1"), "invalid byte between ranges (negative)", []byte("/\ufffdindex.html?test=test1"))
}

func getTransaction() *engine.Transaction {
	waf := engine.NewWaf()
	return waf.NewTransaction()
}

func BenchmarkValidateByteRange(b *testing.B) {
	ranges := "9,10,13,32-126,128-255"
	op := &validateByteRange{}
	if err := op.Init(ranges); err != nil {
		b.Error("Cannot init byte range operator")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		op.Evaluate(nil, "/\ufffdindex.html?test=test1")
	}
}
