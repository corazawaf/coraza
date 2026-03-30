// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.geoLookup

package operators

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs geolocation lookup using the IP address in input against a configured database.
// Sets GEO collection variables (GEO:COUNTRY_CODE, GEO:REGION, etc.) for use in subsequent rules.
// Note: Currently returns unconditionalMatch (stub implementation) - requires geolocation database configuration.
//
// Arguments:
// None. Operates on REMOTE_ADDR or the target variable specified in the rule.
//
// Returns:
// true (always matches, allowing subsequent rules to use GEO variables)
//
// Example:
// ```
// # Perform geolocation lookup and populate GEO variables
// SecRule REMOTE_ADDR "@geoLookup" "phase:1,id:199,nolog,pass"
//
// # Block requests from specific countries
// SecRule GEO:COUNTRY_CODE "@streq CN" "id:200,deny,log"
// ```
func newGeoLookup(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	return &unconditionalMatch{}, nil
}

func init() {
	Register("geoLookup", newGeoLookup)
}
