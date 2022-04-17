//go:build tinygo
// +build tinygo

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
	"errors"
	"io"

	"github.com/corazawaf/coraza/v2/types/variables"
)

// This is only intended for compatibility, xpath is not supported
// This hack should work for OWASP CRS
// This skeleton may be used for other plugins
type xmlBodyProcessor struct {
	values   []string
	contents []string
}

func (xbp *xmlBodyProcessor) Read(_ io.Reader, _ Options) error {
	return errors.New("not implemented")
}

func (xbp *xmlBodyProcessor) Collections() CollectionsMap {
	return CollectionsMap{}
}

func (xbp *xmlBodyProcessor) Find(_ string) (map[string][]string, error) {
	return nil, errors.New("not implemented")
}

func (xbp *xmlBodyProcessor) VariableHook() variables.RuleVariable {
	return 0
}

var (
	_ BodyProcessor = &xmlBodyProcessor{}
)
