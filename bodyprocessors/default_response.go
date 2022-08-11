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
	"io"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type defaultResponseBodyProcessor struct{}

func (*defaultResponseBodyProcessor) ProcessRequest(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {
	return nil
}

func (*defaultResponseBodyProcessor) ProcessResponse(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {
	bts, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	(collections[variables.ResponseBody]).(*collection.Simple).Set(string(bts))
	return nil
}

var _ BodyProcessor = &defaultResponseBodyProcessor{}

func init() {
	Register("default_response", func() BodyProcessor {
		return &defaultResponseBodyProcessor{}
	})
}
