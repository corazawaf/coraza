// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"io/fs"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/io"
	"github.com/corazawaf/coraza/v3/internal/seclang"
)

// Parser is an interface for parsing SecLang rules
type Parser interface {
	FromFile(string) error
	FromString(string) error
}

// ParserConfig is an interface for configuring the parser
type ParserConfig interface {
	WithRoot(root fs.FS) ParserConfig
}

// NewParser creates a new SecLang parser
func NewParser(config ParserConfig) Parser {
	return seclang.NewParser(corazawaf.NewWAF())
}

type parserConfig struct {
	root fs.FS
}

func (c *parserConfig) WithRoot(root fs.FS) ParserConfig {
	ret := &parserConfig{root: c.root}
	ret.root = root
	return ret
}

// NewParserConfig creates a new parser configuration
func NewParserConfig() ParserConfig {
	return &parserConfig{
		root: io.OSFS{},
	}
}
