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

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

// CollectionsMap is used to store results for collections, example:
// REQUEST_HEADERS:
//   cookies: [cookie1: value1, cookie2: value2]
//   user-agent: ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"]
type CollectionsMap map[variables.RuleVariable]map[string][]string

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
}

// BodyProcessor interface is used to create
// body processors for different content-types.
// They are able to read the body, force a collection.
// Hook to some variable and return data based on special
// expressions like XPATH, JQ, etc.
type BodyProcessor interface {
	// Read will process the body and initialize the body processor
	// It will return an error if the body is not valid
	Read(reader io.Reader, options Options) error
	// Collections returns a map of collections, for example,
	// the ARGS_POST variables from the REQUEST_BODY.
	Collections() CollectionsMap
	// Find returns the values in the body based on the input string
	// A string might be an xpath, a regex, a variable name, etc
	// The find function is responsible of transforming the input
	// string into a valid usable expression
	Find(string) (map[string][]string, error)
	// VariableHook tells the transaction to hook a variable
	// to the body processor, it will execute Find
	// rather than read it from the collections map
	VariableHook() variables.RuleVariable
}

type bodyProcessorWrapper = func() BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

// RegisterPlugin registers a body processor
// by name. If the body processor is already registered,
// it will be overwritten
func RegisterPlugin(name string, fn func() BodyProcessor) {
	processors[name] = fn
}

// GetBodyProcessor returns a body processor by name
// If the body processor is not found, it returns an error
func GetBodyProcessor(name string) (BodyProcessor, error) {
	if fn, ok := processors[name]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}

func init() {
	RegisterPlugin("json", func() BodyProcessor {
		return &jsonBodyProcessor{}
	})
	RegisterPlugin("urlencoded", func() BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
	RegisterPlugin("multipart", func() BodyProcessor {
		return &multipartBodyProcessor{}
	})
	RegisterPlugin("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
