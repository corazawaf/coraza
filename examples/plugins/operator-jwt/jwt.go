// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package jwtop

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/operators"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/golang-jwt/jwt/v4"
)

type jwtOp struct {
	signMethod string
	secret     macro.Macro
}

var _ rules.Operator = (*jwtOp)(nil)

func newJWT(options rules.OperatorOptions) (rules.Operator, error) {
	spl := strings.SplitN(options.Arguments, " ", 2)
	if len(spl) != 2 {
		return nil, fmt.Errorf("Invalid syntax for operator @jwt. Syntax: \"@jwt ALG KEY\"")
	}
	secretMacro, err := macro.NewMacro(spl[1])
	if err != nil {
		return nil, fmt.Errorf("@jwt operator error: " + err.Error())
	}
	return &jwtOp{
		secret: secretMacro,
	}, nil
}

func (o *jwtOp) Evaluate(tx rules.TransactionState, value string) bool {
	secret := o.secret.Expand(tx)
	if strings.HasPrefix("Bearer ", value) && len(value) > 7 {
		value = value[7:]
	}
	token, err := jwt.Parse(value, func(token *jwt.Token) (interface{}, error) {
		if o.signMethod == "hmac" {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		} else {
			return nil, fmt.Errorf("@jwt operator: Unsupported signing method %s", o.signMethod)
		}

		return secret, nil
	})
	if err != nil {
		return false
	}
	t, err := flattenToken(token)
	if err != nil {
		return false
	}
	// maybe we could add an option to skip claims validation
	if err := token.Claims.Valid(); err != nil {
		tx.Variables().TX().SetIndex("jwt_error", 0, err.Error())
		return false
	}
	for key, values := range t {
		tx.Variables().ArgsPost().SetIndex(key, 0, values)
	}
	return true

}

func flattenToken(token *jwt.Token) (map[string]string, error) {
	headMap, err := interfaceToMap(token.Header)
	if err != nil {
		return nil, err
	}
	claimsMap, err := interfaceToMap(token.Claims.(jwt.MapClaims))
	if err != nil {
		return nil, err
	}
	res := make(map[string]string, len(headMap)+len(claimsMap))
	for k, v := range headMap {
		res[fmt.Sprintf("jwt.header.%s", k)] = v
	}
	for k, v := range claimsMap {
		res[fmt.Sprintf("jwt.claims.%s", k)] = v
	}
	return res, nil
}

func interfaceToMap(data map[string]interface{}) (map[string]string, error) {
	result := make(map[string]string)
	for key, value := range data {
		switch value := value.(type) {
		case []interface{}:
			m := map[string]interface{}{}
			for i, v := range value {
				m[strconv.Itoa(i)] = v
			}
			// we set the parent key to count the number of items
			result[key] = strconv.Itoa(len(m))

			m2, err := interfaceToMap(m)
			if err != nil {
				return nil, err
			}
			for k, v := range m2 {
				result[fmt.Sprintf("%s.%s", key, k)] = v
			}
		case string:
			result[key] = value
		case int:
			result[key] = strconv.Itoa(value)
		case nil:
			result[key] = ""
		case float64:
			result[key] = strconv.FormatFloat(value, 'f', -1, 64)
		case bool:
			result[key] = strconv.FormatBool(value)
		case map[string]interface{}:
			subMap, err := interfaceToMap(value)
			if err != nil {
				return nil, err
			}
			for k, v := range subMap {
				result[fmt.Sprintf("%s.%s", key, k)] = v
			}
		default:
			return nil, fmt.Errorf("failed to unmarshall %s", value)
		}
	}
	return result, nil
}

func init() {
	operators.Register("jwt", newJWT)
}
