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
package transaction

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// ParseRequestReader Parses binary request including body,
// this helper only support http/1.1 and http/1.0
// This function does not run ProcessConnection
// This function will buffer the whole buffer in memory
func ParseRequestReader(tx *coraza.Transaction, data io.Reader) (*types.Interruption, error) {
	// For dumb reasons we must read the headers and look for the Host header,
	// this function is intended for proxies and the RFC says that a Host must not be parsed...
	// Maybe some time I will create a prettier fix
	scanner := bufio.NewScanner(data)
	// read request line
	scanner.Scan()
	spl := strings.SplitN(scanner.Text(), " ", 3)
	if len(spl) != 3 {
		return nil, fmt.Errorf("invalid request line")
	}
	tx.ProcessURI(spl[1], spl[0], spl[2])
	for scanner.Scan() {
		l := scanner.Text()
		if l == "" {
			// It should mean we are now in the request body...
			break
		}
		spl := strings.SplitN(l, ":", 2)
		if len(spl) != 2 {
			return nil, fmt.Errorf("invalid request header")
		}
		k := strings.Trim(spl[0], " ")
		v := strings.Trim(spl[1], " ")
		tx.AddRequestHeader(k, v)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	cth := tx.Variables.RequestHeaders.Get("content-type")
	ct := ""
	if len(cth) > 0 {
		ct = cth[0]
	}
	ct = strings.Split(ct, ";")[0]
	for scanner.Scan() {

		if _, err := tx.RequestBodyBuffer.Write(scanner.Bytes()); err != nil {
			return nil, fmt.Errorf("cannot write to request body to buffer")
		}
		// urlencoded cannot end with CRLF
		if ct != "application/x-www-form-urlencoded" {
			if _, err := tx.RequestBodyBuffer.Write([]byte{'\r', '\n'}); err != nil {
				return nil, fmt.Errorf("cannot write to request body to buffer")
			}
		}
	}
	return tx.ProcessRequestBody()
}
