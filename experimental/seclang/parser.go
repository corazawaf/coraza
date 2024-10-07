// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"errors"
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

type parser struct {
	Parser
}

func unwrapErr(err error) error {
	if err == nil {
		return nil
	}

	if uErr := errors.Unwrap(err); uErr != nil {
		if pErr, ok := uErr.(seclang.ParsingError); ok {
			return pErr
		}
	}

	return err
}

func (p parser) FromFile(profilePath string) error {
	return unwrapErr(p.Parser.FromFile(profilePath))
}

func (p parser) FromString(data string) error {
	return unwrapErr(p.Parser.FromString(data))
}

// ParserConfig is an interface for configuring the parser
type ParserConfig interface {
	WithRoot(root fs.FS) ParserConfig
}

// NewParser creates a new SecLang parser
func NewParser(config ParserConfig) Parser {
	p := seclang.NewParser(corazawaf.NewWAF())
	p.SetRoot(config.(*parserConfig).root)
	return parser{p}
}

type parserConfig struct {
	root fs.FS
}

func (c *parserConfig) WithRoot(root fs.FS) ParserConfig {
	ret := &parserConfig{}
	ret.root = root
	return ret
}

// NewParserConfig creates a new parser configuration
func NewParserConfig() ParserConfig {
	return &parserConfig{
		root: io.OSFS{},
	}
}
