// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import (
	"io"
	"io/fs"
)

// BodyProcessorOptions are used by BodyProcessors to provide some settings
// like a path to store temporary files.
// Implementations may ignore the options.
type BodyProcessorOptions struct {
	// Mime is the type of the body, it may contain parameters
	// like charset, boundary, etc.
	Mime string
	// StoragePath is the path where the body will be stored
	StoragePath string
	// FileMode is the mode of the file that will be created
	FileMode fs.FileMode
	// DirMode is the mode of the directory that will be created
	DirMode fs.FileMode
}

// BodyProcessor interface is used to create
// body processors for different content-types.
// They are able to read the body, force a collection.
// Hook to some variable and return data based on special
// expressions like XPATH, JQ, etc.
type BodyProcessor interface {
	ProcessRequest(reader io.Reader, variables TransactionVariables, options BodyProcessorOptions) error
	ProcessResponse(reader io.Reader, variables TransactionVariables, options BodyProcessorOptions) error
}
