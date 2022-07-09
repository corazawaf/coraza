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

package operators

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/golang-jwt/jwt/v4"
)

type jwtAlg int

const (
	jwtHMAC = iota
)

type jwtOp struct {
	method jwtAlg
	secret []byte
}

func (o *jwtOp) Init(options coraza.RuleOperatorOptions) error {
	return nil
}

func (o *jwtOp) Evaluate(tx *coraza.Transaction, value string) bool {
	value = strings.TrimPrefix(value, "Bearer ")
	token, err := jwt.Parse(value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		var ok bool
		if o.method == jwtHMAC {
			_, ok = token.Method.(*jwt.SigningMethodHMAC)
		} else {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		if !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return o.secret, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		dst := map[string]string{}
		mapFlatten("", claims, dst)

		return true
	} else {
		tx.Waf.Logger.Debug("JWT: %s", err.Error())
		return false
	}
}

func mapFlatten(prefix string, src map[string]interface{}, dest map[string]string) {
	if len(prefix) > 0 {
		prefix += "."
	}
	for k, v := range src {
		switch child := v.(type) {
		case map[string]interface{}:
			mapFlatten(prefix+k, child, dest)
		case []interface{}:
			for i := 0; i < len(child); i++ {
				dest[prefix+k+"."+strconv.Itoa(i)] = anyToStr(child[i])
			}
		default:
			dest[prefix+k] = anyToStr(v)
		}
	}
}

func anyToStr(input interface{}) string {
	switch value := input.(type) {
	case string:
		return value
	case int:
		return strconv.Itoa(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	default:
		return ""
	}
}

var _ coraza.RuleOperator = &jwtOp{}

func init() {
	Register("jwt", func() coraza.RuleOperator {
		return &jwtOp{}
	})
}
