// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestIPTrieCoraza(t *testing.T) {
	tests := []struct {
		name      string
		args      string
		queryIP   string
		wantMatch bool
	}{
		{
			name:      "Single IPv4 exact",
			args:      "192.168.1.1",
			queryIP:   "192.168.1.1",
			wantMatch: true,
		},
		{
			name:      "IPv4 CIDR match",
			args:      "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
			queryIP:   "10.254.1.2",
			wantMatch: true,
		},
		{
			name:      "IPv4 CIDR no match",
			args:      "10.0.0.0/8",
			queryIP:   "11.0.0.1",
			wantMatch: false,
		},
		{
			name:      "IPv6 CIDR match",
			args:      "2001:db8::/32",
			queryIP:   "2001:db8:ffff::1",
			wantMatch: true,
		},
		{
			name:      "Large subnets list (8+ entries)",
			args:      "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6, 7.7.7.7, 8.8.8.8, 10.0.0.0/16",
			queryIP:   "10.0.5.99",
			wantMatch: true,
		},
		{
			name:      "IPv6 trie match (8+ IPv6 subnets)",
			args:      "2001:db8:1::/48, 2001:db8:2::/48, 2001:db8:3::/48, 2001:db8:4::/48, 2001:db8:5::/48, 2001:db8:6::/48, 2001:db8:7::/48, 2001:db8:8::/48",
			queryIP:   "2001:db8:5::abcd",
			wantMatch: true,
		},
		{
			name:      "IPv6 trie no match (8+ IPv6 subnets)",
			args:      "2001:db8:1::/48, 2001:db8:2::/48, 2001:db8:3::/48, 2001:db8:4::/48, 2001:db8:5::/48, 2001:db8:6::/48, 2001:db8:7::/48, 2001:db8:8::/48",
			queryIP:   "2001:db8:9::1",
			wantMatch: false,
		},
		{
			name:      "Invalid IP returns false",
			args:      "10.0.0.0/8",
			queryIP:   "not-an-ip",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, err := newIPMatch(plugintypes.OperatorOptions{Arguments: tt.args})
			if err != nil {
				t.Fatalf("unexpected error creating ipMatch operator: %v", err)
			}
			got := op.Evaluate(nil, tt.queryIP)
			if got != tt.wantMatch {
				t.Errorf("ipMatch.Evaluate(%s) = %v, want %v", tt.queryIP, got, tt.wantMatch)
			}
		})
	}
}

func benchmarkCorazaIPMatch(b *testing.B, numCIDRs int) {
	subnets := ""
	for i := 0; i < numCIDRs; i++ {
		a := (i >> 16) & 0xFF
		bByte := (i >> 8) & 0xFF
		c := i & 0xFF
		if i > 0 {
			subnets += ", "
		}
		subnets += fmt.Sprintf("10.%d.%d.%d/32", a, bByte, c)
	}

	op, err := newIPMatch(plugintypes.OperatorOptions{Arguments: subnets})
	if err != nil {
		b.Fatalf("failed to create ipMatch operator: %v", err)
	}

	targetIP := fmt.Sprintf("10.%d.%d.%d", (numCIDRs-1)>>16, ((numCIDRs-1)>>8)&0xFF, (numCIDRs-1)&0xFF)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = op.Evaluate(nil, targetIP)
	}
}

func BenchmarkCorazaIPMatch_10(b *testing.B)    { benchmarkCorazaIPMatch(b, 10) }
func BenchmarkCorazaIPMatch_100(b *testing.B)   { benchmarkCorazaIPMatch(b, 100) }
func BenchmarkCorazaIPMatch_1000(b *testing.B)  { benchmarkCorazaIPMatch(b, 1000) }
func BenchmarkCorazaIPMatch_10000(b *testing.B) { benchmarkCorazaIPMatch(b, 10000) }
