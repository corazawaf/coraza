// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/corazawaf/coraza/v3/rules"
)

// Options are used by BodyProcessors to provide some settings
// like a path to store temporary files.
// Implementations may ignore the options.
type Options struct {
	// Mime is the type of the body, it may contain parameters
	// like charset, boundary, etc.
	Mime string
	// StoragePath is the path where the body will be stored
	StoragePath string
	// FileMode is the mode of the file that will be created
	FileMode fs.FileMode
	// DirMode is the mode of the directory that will be created
	DirMode fs.FileMode
	// Strict use strict parsing for XML or others body processors
	Strict bool
}

// BodyProcessor interface is used to create
// body processors for different content-types.
// They are able to read the body, force a collection.
// Hook to some variable and return data based on special
// expressions like XPATH, JQ, etc.
type BodyProcessor interface {
	ProcessRequest(reader io.Reader, variables rules.TransactionVariables, options Options) error
	ProcessResponse(reader io.Reader, variables rules.TransactionVariables, options Options) error
}

type bodyProcessorWrapper = func() BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

// Register registers a body processor
// by name. If the body processor is already registered,
// it will be overwritten
func Register(name string, fn func() BodyProcessor) {
	processors[name] = fn
}

// Get returns a body processor by name
// If the body processor is not found, it returns an error
func Get(name string) (BodyProcessor, error) {
	if fn, ok := processors[strings.ToLower(name)]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}
