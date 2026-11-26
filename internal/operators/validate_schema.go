// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.validateSchema

package operators

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// Description:
// Validates JSON request or response bodies against a JSON Schema specification.
// Automatically retrieves JSON data from TX variables (json_request_body or json_response_body)
// based on the current phase. Returns true if validation fails (schema violation).
//
// Arguments:
// Path to JSON Schema file (relative to configured root filesystem).
// Only JSON Schema format (.json) is currently supported.
//
// Returns:
// true if JSON validation fails (violation), false if JSON is valid or no data to validate
//
// Example:
// ```seclang
// # Validate request body against API schema
// SecRule REQUEST_BODY "@validateSchema /schemas/api-request.json" "id:197,deny,log,phase:2"
//
// # Validate response body schema
// SecRule RESPONSE_BODY "@validateSchema /schemas/api-response.json" "id:198,log,phase:4"
// ```
type validateSchema struct {
	jsonSchema *jsonschema.Schema
}

var _ plugintypes.Operator = (*validateSchema)(nil)

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

	schema, err := memoizeDo(options.Memoizer, memoizeKey("validateSchema", string(schemaData)), func() (any, error) {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaData))
		if err != nil {
			return nil, fmt.Errorf("validating schema as JSON: %w", err)
		}

		const schemaURL = "coraza:///validate-schema.json"
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		// Preserve HTTP references in operator-provided schemas and keep
		// filesystem access scoped to the configured root.
		httpLoader := &schemaHTTPClient{client: http.Client{Timeout: 10 * time.Second}}
		compiler.UseLoader(jsonschema.SchemeURLLoader{
			"http":  httpLoader,
			"https": httpLoader,
		})
		if err := compiler.AddResource(schemaURL, doc); err != nil {
			return nil, fmt.Errorf("adding JSON schema: %w", err)
		}
		schema, err := compiler.Compile(schemaURL)
		if err != nil {
			return nil, fmt.Errorf("compiling JSON schema: %w", err)
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

type schemaHTTPClient struct {
	client http.Client
}

func (l *schemaHTTPClient) Load(url string) (any, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching JSON schema: HTTP %d", resp.StatusCode)
	}
	return jsonschema.UnmarshalJSON(resp.Body)
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
	js, err := jsonschema.UnmarshalJSON(strings.NewReader(data))
	if err != nil {
		return false
	}

	// Use the compiled schema validator
	return o.jsonSchema.Validate(js) == nil
}

func init() {
	Register("validateSchema", NewValidateSchema)
}
