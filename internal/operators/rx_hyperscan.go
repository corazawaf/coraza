// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/flier/gohs/hyperscan"
)

type rxObj struct {
	Pattern  string
	Database hyperscan.BlockDatabase
	Pool     sync.Pool
}

func (obj *rxObj) Allocate() (*hyperscan.Scratch, func()) {
	scratch, _ := obj.Pool.Get().(*hyperscan.Scratch)
	return scratch, func() { obj.Pool.Put(scratch) }
}

type rxDatabase []*rxObj

func (r *rxDatabase) Add(pattern string) (*rxObj, error) {
	// first we validate the pattern is not there
	for _, rx := range *r {
		if rx.Pattern == pattern {
			return rx, nil
		}
	}
	// Pattern not found
	re := hyperscan.NewPattern(pattern, hyperscan.DotAll|hyperscan.SomLeftMost)
	db, err := hyperscan.NewBlockDatabase(re)
	if err != nil {
		return nil, fmt.Errorf("hyperscan: unable to compile pattern \"%s\": %s\n", re.String(), err.Error())
	}
	d := &rxObj{
		Pattern: pattern,
		Pool: sync.Pool{
			New: func() interface{} {
				scratch, err := hyperscan.NewManagedScratch(db)
				if err != nil {
					fmt.Fprint(os.Stderr, "Hyperscan ERROR: Unable to allocate scratch space. Exiting.\n")
					os.Exit(-1)
				}
				return scratch
			},
		},
	}
	*r = append(*r, d)
	return d, nil
}

var rxDb rxDatabase = []*rxObj{}

type rx2 struct {
	db *rxObj
}

var _ plugintypes.Operator = (*rx)(nil)

func (o *rx2) Evaluate(tx plugintypes.TransactionState, value string) bool {
	scratch, closer := o.db.Allocate()
	defer closer()
	matches := false
	counter := int32(0)
	bts := []byte(value)
	if err := o.db.Database.Scan(bts, scratch, func(id uint, from, to uint64, flags uint, data interface{}) error {
		// FYI, hyperscan events are ordered
		i := atomic.LoadInt32(&counter)
		if i >= 10 {
			matches = true
			return nil
		}
		start := bytes.LastIndexByte(bts[:from], '\n')
		end := int(to) + bytes.IndexByte(bts[to:], '\n')
		if start == -1 {
			start = 0
		} else {
			start++
		}

		if end == -1 {
			end = len(bts)
		}
		if tx.Capturing() {
			tx.CaptureField(int(i), string(bts[start:end]))
		}
		atomic.AddInt32(&counter, 1)
		return nil
	}, nil); err != nil {
		tx.DebugLogger().Error().Err(err)
		return false
	}

	return matches || counter > 0
}

func newRX2(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	rx := &rx2{}
	db, err := rxDb.Add(options.Arguments)
	if err != nil {
		return nil, err
	}
	rx.db = db
	return rx, nil
}
