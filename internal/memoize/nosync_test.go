// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.no_memoize

package memoize

import (
	"errors"
	"fmt"
	"regexp"
	"testing"
)

func TestDo(t *testing.T) {
	t.Cleanup(Reset)

	m := NewMemoizer(1)
	expensiveCalls := 0

	expensive := func() (any, error) {
		expensiveCalls++
		return expensiveCalls, nil
	}

	result, err := m.Do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key1", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key2", expensive)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}
}

func TestFailedCall(t *testing.T) {
	t.Cleanup(Reset)

	m := NewMemoizer(1)
	calls := 0

	twoForTheMoney := func() (any, error) {
		calls++
		if calls == 1 {
			return calls, errors.New("Try again")
		}
		return calls, nil
	}

	result, err := m.Do("key1", twoForTheMoney)
	if err == nil {
		t.Fatalf("expected error")
	}
	if want, have := 1, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}

	result, err = m.Do("key1", twoForTheMoney)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if want, have := 2, result.(int); want != have {
		t.Fatalf("unexpected value, want %d, have %d", want, have)
	}
}

func TestRelease(t *testing.T) {
	t.Cleanup(Reset)

	m1 := NewMemoizer(1)
	m2 := NewMemoizer(2)

	calls := 0
	fn := func() (any, error) {
		calls++
		return calls, nil
	}

	_, _ = m1.Do("shared", fn)
	_, _ = m2.Do("shared", fn)
	_, _ = m1.Do("only-waf1", fn)

	Release(1)

	if _, ok := cache.Load("shared"); !ok {
		t.Fatal("shared entry should still exist after releasing waf-1")
	}
	if _, ok := cache.Load("only-waf1"); ok {
		t.Fatal("only-waf1 entry should be deleted after releasing its sole owner")
	}

	Release(2)
	if _, ok := cache.Load("shared"); ok {
		t.Fatal("shared entry should be deleted after releasing all owners")
	}
}

func TestReset(t *testing.T) {
	m := NewMemoizer(1)
	_, _ = m.Do("k1", func() (any, error) { return 1, nil })
	_, _ = m.Do("k2", func() (any, error) { return 2, nil })

	Reset()

	if _, ok := cache.Load("k1"); ok {
		t.Fatal("cache should be empty after Reset")
	}
	if _, ok := cache.Load("k2"); ok {
		t.Fatal("cache should be empty after Reset")
	}
}

// cacheLen counts the number of entries in the global cache.
func cacheLen() int {
	n := 0
	cache.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// crsLikePatterns generates n CRS-scale regex patterns.
func crsLikePatterns(n int) []string {
	patterns := make([]string, n)
	for i := range patterns {
		patterns[i] = fmt.Sprintf(`(?i)pattern_%d_[a-z]{2,8}\d+`, i)
	}
	return patterns
}

func TestMemoizeScaleMultipleOwners(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in short mode")
	}
	t.Cleanup(Reset)

	const (
		numOwners   = 10
		numPatterns = 300
	)

	patterns := crsLikePatterns(numPatterns)
	calls := 0
	fn := func(p string) func() (any, error) {
		return func() (any, error) {
			calls++
			return regexp.Compile(p)
		}
	}

	for i := uint64(1); i <= numOwners; i++ {
		m := NewMemoizer(i)
		for _, p := range patterns {
			if _, err := m.Do(p, fn(p)); err != nil {
				t.Fatal(err)
			}
		}
	}

	if calls != numPatterns {
		t.Fatalf("expected %d compilations, got %d", numPatterns, calls)
	}
	if n := cacheLen(); n != numPatterns {
		t.Fatalf("expected %d cache entries, got %d", numPatterns, n)
	}

	// Release all owners; cache should be empty.
	for i := uint64(1); i <= numOwners; i++ {
		Release(i)
	}
	if n := cacheLen(); n != 0 {
		t.Fatalf("expected empty cache after releasing all owners, got %d", n)
	}
}

func TestCacheGrowthWithoutClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in short mode")
	}
	t.Cleanup(Reset)

	const (
		numOwners   = 100
		numPatterns = 300
	)

	patterns := crsLikePatterns(numPatterns)
	fn := func(p string) func() (any, error) {
		return func() (any, error) {
			return regexp.Compile(p)
		}
	}

	for i := uint64(1); i <= numOwners; i++ {
		m := NewMemoizer(i)
		for _, p := range patterns {
			if _, err := m.Do(p, fn(p)); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Every entry should have all owners.
	cache.Range(func(_, value any) bool {
		e := value.(*entry)
		e.mu.Lock()
		defer e.mu.Unlock()
		if len(e.owners) != numOwners {
			t.Fatalf("expected %d owners per entry, got %d", numOwners, len(e.owners))
		}
		return true
	})
}

func TestCacheBoundedWithClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in short mode")
	}
	t.Cleanup(Reset)

	const (
		numCycles   = 100
		numPatterns = 300
	)

	patterns := crsLikePatterns(numPatterns)
	fn := func(p string) func() (any, error) {
		return func() (any, error) {
			return regexp.Compile(p)
		}
	}

	for i := uint64(1); i <= numCycles; i++ {
		m := NewMemoizer(i)
		for _, p := range patterns {
			if _, err := m.Do(p, fn(p)); err != nil {
				t.Fatal(err)
			}
		}
		Release(i)
	}

	if n := cacheLen(); n != 0 {
		t.Fatalf("expected empty cache after all releases, got %d", n)
	}
}

func BenchmarkCompileWithoutMemoize(b *testing.B) {
	patterns := crsLikePatterns(300)
	for _, numWAFs := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("WAFs=%d", numWAFs), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for w := 0; w < numWAFs; w++ {
					for _, p := range patterns {
						if _, err := regexp.Compile(p); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}

func BenchmarkCompileWithMemoize(b *testing.B) {
	patterns := crsLikePatterns(300)
	for _, numWAFs := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("WAFs=%d", numWAFs), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Reset()
				for w := 0; w < numWAFs; w++ {
					m := NewMemoizer(uint64(w + 1))
					for _, p := range patterns {
						if _, err := m.Do(p, func() (any, error) {
							return regexp.Compile(p)
						}); err != nil {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}

func BenchmarkRelease(b *testing.B) {
	patterns := crsLikePatterns(300)
	for _, numOwners := range []int{1, 10, 100} {
		b.Run(fmt.Sprintf("Owners=%d", numOwners), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				Reset()
				for o := 0; o < numOwners; o++ {
					m := NewMemoizer(uint64(o + 1))
					for _, p := range patterns {
						m.Do(p, func() (any, error) {
							return regexp.Compile(p)
						})
					}
				}
				b.StartTimer()
				for o := 0; o < numOwners; o++ {
					Release(uint64(o + 1))
				}
			}
		})
	}
}
