//go:build tinygo
// +build tinygo

// Copyright 2022 The CorazaWAF Authors
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

	"github.com/corazawaf/coraza/v3/collection"
)

type xmlBodyProcessor struct{}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, collections []collection.Collection, options Options) error {
	return errors.New("not implemented")
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, collections []collection.Collection, options Options) error {
	return errors.New("not implemented")
}

var _ BodyProcessor = &xmlBodyProcessor{}

func init() {
	Register("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
