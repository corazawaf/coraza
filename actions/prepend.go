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

package actions

import (
	"io"

	"github.com/jptosso/coraza-waf"
)

type Prepend struct {
	data string
}

func (a *Prepend) Init(r *coraza.Rule, data string) error {
	a.data = data
	return nil
}

func (a *Prepend) Evaluate(r *coraza.Rule, tx *coraza.Transaction) {
	if !tx.Waf.ContentInjection {
		tx.Waf.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := tx.MacroExpansion(a.data)
	buf := coraza.NewBodyReader(tx.Waf.TmpDir, tx.Waf.RequestBodyInMemoryLimit)
	_, err := buf.Write([]byte(data))
	if err != nil {
		tx.Waf.Logger.Debug("failed to write buffer while evaluating prepend action")
	}
	reader := tx.ResponseBodyBuffer.Reader()
	_, err = io.Copy(buf, reader)
	if err != nil {
		tx.Waf.Logger.Debug("failed to append response buffer while evaluating prepend action")
	}
	// We overwrite the response body buffer with the new buffer
	*tx.ResponseBodyBuffer = *buf
	// Maybe in the future we could add the prepend function to the BodyBuffer
}

func (a *Prepend) Type() int {
	return coraza.ACTION_TYPE_NONDISRUPTIVE
}
