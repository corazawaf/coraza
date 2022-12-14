// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Proxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionProxys ARE NOT concurrent safe
type Proxy struct {
	data     []*Map
	name     string
	variable variables.RuleVariable
}

func (c *Proxy) Find(query *Query) []types.MatchData {
	var res []types.MatchData
	for _, c := range c.data {
		// we use a small hack to force the query to be case insensitive
		cs := c.isKeySensitiveKey
		c.isKeySensitiveKey = false
		res = append(res, c.Find(query)...)
		c.isKeySensitiveKey = cs
	}
	return res
}

// Name returns the name for the current CollectionProxy
func (c *Proxy) Name() string {
	return c.name
}

// Get returns the data for the key
func (c *Proxy) Get(key string) []string {
	var res []string
	for _, c := range c.data {
		res = append(res, c.Get(key)...)
	}
	return res
}

// Data returns merged data from all CollectionMap
func (c *Proxy) Data() map[string][]string {
	res := map[string][]string{}
	for _, c := range c.data {
		for k, v := range c.Data() {
			res[k] = append(res[k], v...)
		}
	}
	return res
}

// Reset the current CollectionProxy
func (c *Proxy) Reset() {
}

var _ Collection = &Proxy{}

// NewProxy returns a Proxy collection that merges all collections
func NewProxy(variable variables.RuleVariable, data ...*Map) *Proxy {
	return &Proxy{
		name:     variable.Name(),
		variable: variable,
		data:     data,
	}
}
