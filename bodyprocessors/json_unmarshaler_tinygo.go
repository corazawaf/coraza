// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package bodyprocessors

import (
	"github.com/tidwall/gjson"
)

func jsonUnmarshal(data []byte) (interface{}, error) {
	return gjson.Parse(string(data)).Value(), nil
}
