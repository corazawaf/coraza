// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.validateSchema
// +build !tinygo,!coraza.disabled_operators.validateSchema

package operators

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/kaptinlin/jsonschema"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/memoize"
	"github.com/corazawaf/coraza/v3/types"
)

type validateSchema struct {
	jsonSchema *jsonschema.Schema
}

var _ plugintypes.Operator = (*validateSchema)(nil)

func md5Hash(b []byte) string {
	hasher := md5.New()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

// NewValidateSchema creates a new validateSchema operator
func NewValidateSchema(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	schemaPath := options.Arguments
	if schemaPath == "" {
		return nil, errors.New("missing schema file path")
	}

	// Determine schema type from file extension
	ext := strings.ToLower(filepath.Ext(schemaPath))
	if ext != ".json" {
		return nil, fmt.Errorf("unsupported schema type: %s, only JSON is supported", ext)
	}

	var (
		schemaData []byte
		err        error
	)

	// Handle file from provided filesystem root
	schemaData, err = fs.ReadFile(options.Root, schemaPath)
	if err != nil {
		return nil, fmt.Errorf("reading schema from root FS: %v", err)
	}

	key := md5Hash(schemaData)
	schema, err := memoize.Do(key, func() (any, error) {
		// Preliminarily validate that the schema is valid JSON
		var jsonSchema any
		if err := json.Unmarshal(schemaData, &jsonSchema); err != nil {
			return nil, fmt.Errorf("validating schema as JSON: %v", err)
		}

		// Compile JSON Schema at creation time
		compiler := jsonschema.NewCompiler()
		schema, err := compiler.Compile(schemaData)
		if err != nil {
			return nil, fmt.Errorf("compiling JSON schema: %v", err)
		}
		return schema, nil
	})
	if err != nil {
		return nil, err
	}

	return &validateSchema{
		jsonSchema: schema.(*jsonschema.Schema),
	}, nil
}

func (o *validateSchema) Evaluate(tx plugintypes.TransactionState, data string) bool {
	// If we're validating a request/response body, try to get data from the TX variable
	var bodyData string

	// Check TX variable for stored raw data from body processors
	if tx != nil {
		txVar := tx.Variables().TX()
		currentPhase := tx.LastPhase()

		// If we're in the response phase, check for response body data first
		if currentPhase >= types.PhaseResponseBody {
			// Try JSON response data, but only if we're in the appropriate phase
			// Response bodies are available starting from phase 4 (PhaseResponseBody)
			jsonRespData := txVar.Get("json_response_body")
			if len(jsonRespData) > 0 && jsonRespData[0] != "" {
				bodyData = jsonRespData[0]
			}
		}

		// If we are in the request phase or later, check for request body data
		if bodyData == "" && currentPhase >= types.PhaseRequestBody {
			// Request bodies are available starting from phase 2 (PhaseRequestBody)
			jsonReqData := txVar.Get("json_request_body")
			if len(jsonReqData) > 0 && jsonReqData[0] != "" {
				bodyData = jsonReqData[0]
			}
		}

		// If we found data in TX, validate it
		if bodyData != "" {
			// Return true if validation fails (violation)
			return !o.isValidJSON(bodyData)
		}
	}

	// If no variable data found or used, try the provided data string
	if data == "" {
		return false
	}

	return !o.isValidJSON(data)
}

// isValidJSON performs comprehensive JSON Schema validation
func (o *validateSchema) isValidJSON(data string) bool {
	// Return true for basic validity if no schema validator is available
	if o.jsonSchema == nil {
		return true
	}

	// Check basic JSON syntax
	var js any
	if err := json.Unmarshal([]byte(data), &js); err != nil {
		return false
	}

	// Use the compiled schema validator
	result := o.jsonSchema.Validate(js)
	return result == nil || result.IsValid()
}

func init() {
	Register("validateSchema", NewValidateSchema)
}
