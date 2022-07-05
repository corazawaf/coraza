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
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
	utils "github.com/corazawaf/coraza/v3/utils/url"
)

type urlencodedBodyProcessor struct {
}

func (_ *urlencodedBodyProcessor) ProcessRequest(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	values, err := utils.ParseQuery(b, "&")
	if err != nil {
		collection[variables.UrlencodedError].SetIndex("", 0, err.Error())
		return nil
	}
	for k, vs := range values {
		collection[variables.ArgsPost].Set(k, vs)
	}
	collection[variables.RequestBody].SetIndex("", 0, b)
	collection[variables.RequestBodyLength].SetIndex("", 0, strconv.Itoa(len(b)))
	return nil
}

func (_ *urlencodedBodyProcessor) ProcessResponse(reader io.Reader, collection [types.VariablesCount]collection.Collection, options Options) error {
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
