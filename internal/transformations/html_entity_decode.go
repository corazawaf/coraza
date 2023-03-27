// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"golang.org/x/net/html"
)

func htmlEntityDecode(data string) (string, error) {
	return html.UnescapeString(data), nil
}
