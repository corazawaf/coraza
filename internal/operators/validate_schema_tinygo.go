// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo && !coraza.disabled_operators.validateSchema
// +build tinygo,!coraza.disabled_operators.validateSchema

package operators

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type validateSchema struct {
	schemaType  string
	schemaPath  string
	schemaData  []byte
	initOnce    sync.Once
	initError   error
}

var _ plugintypes.Operator = (*validateSchema)(nil)

// NewValidateSchema creates a new validateSchema operator
func NewValidateSchema(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	if data == "" {
		return nil, errors.New("schema file path is required")
	}

	var schemaData []byte
	var err error

	// Check if it's a file path and read schema data
	if options.Root != nil {
		// Handle file from provided filesystem root
		schemaData, err = fs.ReadFile(options.Root, data)
		if err != nil {
			return nil, fmt.Errorf("failed to read schema file from root FS: %v", err)
		}
	} else {
		// Direct file access fallback
		schemaData, err = os.ReadFile(data)
		if err != nil {
			return nil, fmt.Errorf("failed to read schema file: %v", err)
		}
	}

	// Determine schema type from file extension
	ext := strings.ToLower(filepath.Ext(data))
	if ext != ".json" {
		return nil, fmt.Errorf("unsupported schema type: %s, must be .json", ext)
	}

	// Preliminarily validate that the schema is valid JSON
	var jsonSchema interface{}
	if err := json.Unmarshal(schemaData, &jsonSchema); err != nil {
		return nil, fmt.Errorf("invalid JSON schema: %v", err)
	}

	operator := &validateSchema{
		schemaType: "json",
		schemaPath: data,
		schemaData: schemaData,
	}

	return operator, nil
}

// initValidators lazily initializes the validators to avoid doing expensive operations during initialization
// In TinyGo there's no real initialization needed since we only do basic validation
func (o *validateSchema) initValidators() error {
	o.initOnce.Do(func() {
		// No initialization needed for TinyGo implementation - just basic validation
	})
	return o.initError
}

func (o *validateSchema) Evaluate(tx plugintypes.TransactionState, data string) bool {
	// Lazy initialize the validators
	if err := o.initValidators(); err != nil {
		// If we can't initialize validators, we can't validate
		return false
	}

	// If we're validating a request/response body, try to get data from the TX variable
	var bodyData string

	// Check TX variable for stored raw data from body processors
	if tx != nil && tx.Variables() != nil && tx.Variables().TX() != nil {
		txVar := tx.Variables().TX()
		
		// Try JSON request data first
		jsonReqData := txVar.Get("json_request_body")
		if len(jsonReqData) > 0 && jsonReqData[0] != "" {
			bodyData = jsonReqData[0]
		} else {
			// Try JSON response data
			jsonRespData := txVar.Get("json_response_body")
			if len(jsonRespData) > 0 && jsonRespData[0] != "" {
				bodyData = jsonRespData[0]
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

	// Return true if validation fails (violation)
	result := o.isValidJSON(data)
	return !result
}

// isValidJSON performs basic JSON syntax validation for TinyGo
func (o *validateSchema) isValidJSON(data string) bool {
	// For TinyGo, just check basic JSON syntax
	var js interface{}
	if err := json.Unmarshal([]byte(data), &js); err != nil {
		return false
	}
	return true
}

func init() {
	Register("validateSchema", NewValidateSchema)
}
