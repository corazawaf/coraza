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
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/url"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type urlencodedBodyProcessor struct {
}

func (*urlencodedBodyProcessor) ProcessRequest(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	values := url.ParseQuery(b, '&')
	argsCol := (collections[variables.ArgsPost]).(*collection.CollectionMap)
	for k, vs := range values {
		argsCol.Set(k, vs)
	}
	(collections[variables.RequestBody]).(*collection.CollectionSimple).Set(b)
	(collections[variables.RequestBodyLength]).(*collection.CollectionSimple).Set(strconv.Itoa(len(b)))
	return nil
}

func (*urlencodedBodyProcessor) ProcessResponse(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error {
	return nil
}

var (
	_ BodyProcessor = &urlencodedBodyProcessor{}
)

func init() {
	Register("urlencoded", func() BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
}
