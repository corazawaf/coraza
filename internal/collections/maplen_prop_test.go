// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

// keys chosen so the case-insensitive map collides two distinct input keys onto
// one stored key, and so Remove sometimes targets an absent key.
var propKeys = []string{"a", "A", "b", "B", "cc", "CC", "absent", "zZ"}

func groundTruth(c *Map) int { return len(c.FindAll()) }

func randValues(r *rand.Rand) []string {
	switch r.Intn(4) {
	case 0:
		return nil
	case 1:
		return []string{}
	default:
		n := r.Intn(5)
		vs := make([]string, n)
		for i := range vs {
			vs[i] = fmt.Sprintf("v%d", i)
		}
		return vs
	}
}

func runPropSeq(t *testing.T, c *Map, r *rand.Rand, steps int) {
	t.Helper()
	for i := 0; i < steps; i++ {
		k := propKeys[r.Intn(len(propKeys))]
		var op string
		switch r.Intn(6) {
		case 0:
			op = fmt.Sprintf("Add(%q)", k)
			c.Add(k, "x")
		case 1:
			vs := randValues(r)
			op = fmt.Sprintf("Set(%q, %v)", k, vs)
			c.Set(k, vs)
		case 2:
			// index 0 / at len / past len / far past len
			cur := len(c.Get(k))
			idx := []int{0, cur, cur + 1, cur + 50}[r.Intn(4)]
			op = fmt.Sprintf("SetIndex(%q, %d)", k, idx)
			c.SetIndex(k, idx, "y")
		case 3:
			op = fmt.Sprintf("Remove(%q)", k)
			c.Remove(k)
		case 4:
			op = "Reset()"
			c.Reset()
		case 5:
			// churn: add then set shorter, exercising cap-reuse branch in Set
			c.Add(k, "p")
			c.Add(k, "q")
			c.Set(k, []string{"r"})
			op = fmt.Sprintf("Add+Add+Set-shorter(%q)", k)
		}
		if want, have := groundTruth(c), c.TotalValues(); want != have {
			t.Fatalf("step %d after %s: stored=%d Len=%d (data=%v)", i, op, want, have, c.data)
		}
	}
}

func TestPropMapLenMatchesStoredValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func() *Map
	}{
		{"case-insensitive", func() *Map { return NewMap(variables.ArgsGet) }},
		{"case-sensitive", func() *Map { return NewCaseSensitiveKeyMap(variables.ArgsGet) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for seed := int64(0); seed < 500; seed++ {
				c := tc.mk()
				runPropSeq(t, c, rand.New(rand.NewSource(seed)), 400)
			}
		})
	}
}

func TestPropNamedCollectionLenMatchesStoredValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		mk   func() *NamedCollection
	}{
		{"case-insensitive", func() *NamedCollection { return NewNamedCollection(variables.ArgsGet) }},
		{"case-sensitive", func() *NamedCollection { return NewCaseSensitiveNamedCollection(variables.ArgsGet) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for seed := int64(0); seed < 500; seed++ {
				c := tc.mk()
				runPropSeq(t, c.Map, rand.New(rand.NewSource(seed)), 400)
			}
		})
	}
}

// Named edge cases that the random walk may under-sample.
func TestMapLenEdgeCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(c *Map)
	}{
		{"remove on empty map", func(c *Map) { c.Remove("nope") }},
		{"remove absent key with entries", func(c *Map) { c.Add("a", "1"); c.Remove("nope") }},
		{"set empty slice on new key", func(c *Map) { c.Set("a", []string{}) }},
		{"set nil on existing key", func(c *Map) { c.Add("a", "1"); c.Set("a", nil) }},
		{"set shorter then longer", func(c *Map) {
			c.Set("a", []string{"1", "2", "3"})
			c.Set("a", []string{"1"})
			c.Set("a", []string{"1", "2", "3", "4"})
		}},
		{"setindex 0 on empty", func(c *Map) { c.SetIndex("a", 0, "v") }},
		{"setindex at len", func(c *Map) { c.Add("a", "1"); c.SetIndex("a", 1, "v") }},
		{"setindex far past len", func(c *Map) { c.Add("a", "1"); c.SetIndex("a", 99, "v") }},
		{"setindex overwrite", func(c *Map) { c.Add("a", "1"); c.SetIndex("a", 0, "v") }},
		{"case collision add", func(c *Map) { c.Add("Key", "1"); c.Add("kEy", "2"); c.Add("KEY", "3") }},
		{"case collision set then remove", func(c *Map) {
			c.Add("Key", "1")
			c.Set("kEy", []string{"a", "b"})
			c.Remove("KEY")
		}},
		{"case collision setindex", func(c *Map) { c.Add("Key", "1"); c.SetIndex("kEy", 5, "z") }},
		{"reset then reuse", func(c *Map) {
			c.Add("a", "1")
			c.Add("b", "2")
			c.Reset()
			c.Add("a", "1")
			c.Set("b", []string{"1", "2"})
		}},
		{"remove after set-empty", func(c *Map) { c.Set("a", nil); c.Remove("a") }},
	} {
		for _, cs := range []struct {
			name string
			mk   func() *Map
		}{
			{"ci", func() *Map { return NewMap(variables.ArgsGet) }},
			{"cs", func() *Map { return NewCaseSensitiveKeyMap(variables.ArgsGet) }},
		} {
			t.Run(tc.name+"/"+cs.name, func(t *testing.T) {
				c := cs.mk()
				tc.run(c)
				if want, have := groundTruth(c), c.TotalValues(); want != have {
					t.Fatalf("stored=%d Len=%d (data=%v)", want, have, c.data)
				}
			})
		}
	}
}

// FuzzMapLen drives the same invariant from a fuzzer-controlled opcode stream.
func FuzzMapLen(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte{1, 0, 0, 3, 2, 2, 2})
	f.Fuzz(func(t *testing.T, ops []byte) {
		for _, c := range []*Map{NewMap(variables.ArgsGet), NewCaseSensitiveKeyMap(variables.ArgsGet)} {
			for i := 0; i+1 < len(ops); i += 2 {
				k := propKeys[int(ops[i+1])%len(propKeys)]
				switch ops[i] % 6 {
				case 0:
					c.Add(k, "x")
				case 1:
					c.Set(k, make([]string, int(ops[i+1])%4))
				case 2:
					c.SetIndex(k, int(ops[i+1])%5, "y")
				case 3:
					c.Remove(k)
				case 4:
					c.Reset()
				case 5:
					c.Set(k, nil)
				}
				if want, have := groundTruth(c), c.TotalValues(); want != have {
					t.Fatalf("op %d key %q: stored=%d Len=%d", ops[i]%6, k, want, have)
				}
			}
		}
	})
}
