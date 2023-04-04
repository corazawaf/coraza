// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.geoLookup

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func newGeoLookup(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &unconditionalMatch{}, nil
}

func init() {
	Register("geoLookup", newGeoLookup)
}
