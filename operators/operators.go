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

package operators

import engine "github.com/jptosso/coraza-waf"

func OperatorsMap() map[string]engine.Operator {
	return map[string]engine.Operator{
		"beginsWith":           &BeginsWith{},
		"rx":                   &Rx{},
		"eq":                   &Eq{},
		"detectSQLi":           &DetectSQLi{},
		"detectXSS":            &DetectXSS{},
		"contains":             &Contains{},
		"endsWith":             &EndsWith{},
		"inspectFile":          &InspectFile{},
		"ge":                   &Ge{},
		"gt":                   &Gt{},
		"le":                   &Le{},
		"lt":                   &Lt{},
		"unconditionalMatch":   &UnconditionalMatch{},
		"within":               &Within{},
		"pmFromFile":           &PmFromFile{},
		"pm":                   &Pm{},
		"validateByteRange":    &ValidateByteRange{},
		"validateUrlEncoding":  &ValidateUrlEncoding{},
		"streq":                &Streq{},
		"ipMatch":              &IpMatch{},
		"ipMatchFromFile":      &IpMatchFromFile{},
		"geoLookup":            &GeoLookup{},
		"rbl":                  &Rbl{},
		"validateUtf8Encoding": &ValidateUtf8Encoding{},
		"noMatch":              &NoMatch{},
		"validateNid":          &ValidateNid{},
	}
}
