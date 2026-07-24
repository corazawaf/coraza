// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"net"
	"net/netip"
)

type iptrieNode struct {
	children [2]*iptrieNode
	isEnd    bool
}

// IPTrie is a bitwise Radix Trie (PATRICIA trie) for high-performance O(W) IP prefix lookups.
type IPTrie struct {
	v4Root *iptrieNode
	v6Root *iptrieNode
	count  int
}

// NewIPTrie constructs an empty IPTrie.
func NewIPTrie() *IPTrie {
	return &IPTrie{
		v4Root: &iptrieNode{},
		v6Root: &iptrieNode{},
	}
}

// InsertPrefix inserts a netip.Prefix into the trie.
func (t *IPTrie) InsertPrefix(prefix netip.Prefix) {
	addr := prefix.Addr().Unmap()
	bits := prefix.Bits()

	var root *iptrieNode
	var bytes []byte

	if addr.Is4() {
		root = t.v4Root
		b4 := addr.As4()
		bytes = b4[:]
	} else if addr.Is6() {
		root = t.v6Root
		b16 := addr.As16()
		bytes = b16[:]
	} else {
		return
	}

	if bits < 0 {
		bits = len(bytes) * 8
	}

	curr := root
	for bitIdx := 0; bitIdx < bits; bitIdx++ {
		byteIdx := bitIdx / 8
		bitOffset := 7 - (bitIdx % 8)
		bitVal := (bytes[byteIdx] >> bitOffset) & 1

		if curr.children[bitVal] == nil {
			curr.children[bitVal] = &iptrieNode{}
		}
		curr = curr.children[bitVal]
	}

	curr.isEnd = true
	t.count++
}

// InsertIPNet converts net.IPNet to netip.Prefix and inserts it into the trie.
func (t *IPTrie) InsertIPNet(ipNet net.IPNet) bool {
	prefix, ok := netipPrefixFromIPNet(ipNet)
	if !ok {
		return false
	}
	t.InsertPrefix(prefix)
	return true
}

// ContainsAddr tests whether clientIP matches any stored CIDR prefix in O(W) time.
func (t *IPTrie) ContainsAddr(clientIP netip.Addr) bool {
	addr := clientIP.Unmap()

	var curr *iptrieNode
	var bytes []byte
	var maxBits int

	if addr.Is4() {
		curr = t.v4Root
		b4 := addr.As4()
		bytes = b4[:]
		maxBits = 32
	} else if addr.Is6() {
		curr = t.v6Root
		b16 := addr.As16()
		bytes = b16[:]
		maxBits = 128
	} else {
		return false
	}

	if curr.isEnd {
		return true
	}

	for bitIdx := 0; bitIdx < maxBits; bitIdx++ {
		byteIdx := bitIdx / 8
		bitOffset := 7 - (bitIdx % 8)
		bitVal := (bytes[byteIdx] >> bitOffset) & 1

		curr = curr.children[bitVal]
		if curr == nil {
			break
		}

		if curr.isEnd {
			return true
		}
	}

	return false
}

// ContainsIP accepts net.IP and checks if it matches any subnet in the trie.
func (t *IPTrie) ContainsIP(ip net.IP) bool {
	if len(ip) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return t.ContainsAddr(addr)
}

func netipPrefixFromIPNet(ipNet net.IPNet) (netip.Prefix, bool) {
	ones, _ := ipNet.Mask.Size()
	addr, ok := netip.AddrFromSlice(ipNet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones), true
}
