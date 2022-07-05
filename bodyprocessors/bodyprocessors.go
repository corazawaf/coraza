// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bodyprocessors

import (
	"fmt"
	"io"
	"io/fs"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
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
}

// BodyProcessor interface is used to create
// body processors for different content-types.
// They are able to read the body, force a collection.
// Hook to some variable and return data based on special
// expressions like XPATH, JQ, etc.
type BodyProcessor interface {
	ProcessRequest(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error
	ProcessResponse(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error
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
	if fn, ok := processors[name]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}
