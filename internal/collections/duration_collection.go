// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"strconv"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/variables"
	"github.com/corazawaf/coraza/v3/types"
)

type Duration struct {
	txInit int64
}

func NewDuration() *Duration {
	return &Duration{
		txInit: time.Now().Unix(),
	}
}

var _ collection.Single = &Duration{}

func (c *Duration) generateDuration() string {
	t := time.Now().Add(-time.Duration(c.txInit)).UnixMilli()
	return strconv.Itoa(int(t))
}

func (c *Duration) FindAll() []types.MatchData {
	return []types.MatchData{
		&corazarules.MatchData{
			Variable_: variables.Duration,
			Value_:    c.generateDuration(),
		},
	}
}

func (c *Duration) Get() string {
	return c.generateDuration()
}

func (c *Duration) Set(value string) {

}

func (c *Duration) Name() string {
	return "Duration"
}
