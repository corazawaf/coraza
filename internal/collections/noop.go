// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
)

var Noop collection.Collection = &noop{}

type noop struct{}

<<<<<<< HEAD
=======
func (c *noop) Get(_ string) []string {
	return []string{}
}

func (c *noop) FindRegex(_ *regexp.Regexp) []types.MatchData {
	return []types.MatchData{}
}

func (c *noop) FindString(_ string) []types.MatchData {
	return []types.MatchData{}
}

>>>>>>> refs/remotes/origin/transform-noops-to-maps
func (c *noop) FindAll() []types.MatchData {
	return nil
}

func (c *noop) Name() string {
	return ""
}
