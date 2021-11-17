// Copyright 2021 Juan Pablo Tosso
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
	"io"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

// This is only intended for compatibility, xpath is not supported
// This hack should work for OWASP CRS
// This skeleton may be used for other plugins
type xmlBodyProcessor struct {
	body string
}

func (xml *xmlBodyProcessor) Read(reader io.Reader, _ string, _ string) error {
	// reader to body
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		xml.body += string(buf[:n])
	}
	return nil
}

func (xml *xmlBodyProcessor) Collections() collectionsMap {
	return collectionsMap{}
}

func (xml *xmlBodyProcessor) Find(expr string) (map[string][]string, error) {
	return map[string][]string{
		"": {xml.body},
	}, nil
}

func (xml *xmlBodyProcessor) VariableHook() variables.RuleVariable {
	return variables.XML
}

var (
	_ BodyProcessor = &xmlBodyProcessor{}
)
