// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.validateSchema

package operators

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/kaptinlin/jsonschema"
	xsdvalidate "github.com/terminalstatic/go-xsd-validate"
)

// Initialize libxml2 for XML validation
var xmlInitOnce sync.Once

type validateSchema struct {
	schemaType string
	schemaPath string
	schemaData []byte
	jsonSchema *jsonschema.Schema
	xsdHandler *xsdvalidate.XsdHandler
	initOnce   sync.Once
	initError  error
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
	var schemaType string
	switch ext {
	case ".json":
		schemaType = "json"
		// Preliminarily validate that the schema is valid JSON
		var jsonSchema interface{}
		if err := json.Unmarshal(schemaData, &jsonSchema); err != nil {
			return nil, fmt.Errorf("invalid JSON schema: %v", err)
		}
	case ".xsd":
		schemaType = "xml"
		// Preliminarily validate that the XSD is valid XML
		var xmlSchema interface{}
		if err := xml.Unmarshal(schemaData, &xmlSchema); err != nil {
			return nil, fmt.Errorf("invalid XML schema: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported schema type: %s, must be .json or .xsd", ext)
	}

	operator := &validateSchema{
		schemaType: schemaType,
		schemaPath: data,
		schemaData: schemaData,
	}

	return operator, nil
}

// initValidators lazily initializes the validators to avoid doing expensive operations during initialization
func (o *validateSchema) initValidators() error {
	var err error
	o.initOnce.Do(func() {
		if o.schemaType == "json" {
			// Initialize JSON Schema validator
			compiler := jsonschema.NewCompiler()

			// Parse the schema
			var schema *jsonschema.Schema
			schema, err = compiler.Compile(o.schemaData)
			if err != nil {
				o.initError = fmt.Errorf("failed to compile JSON schema: %v", err)
				return
			}
			o.jsonSchema = schema

		} else if o.schemaType == "xml" {
			// Initialize libxml2 once
			xmlInitOnce.Do(func() {
				err = xsdvalidate.Init()
				if err != nil {
					o.initError = fmt.Errorf("failed to initialize XML validator: %v", err)
					return
				}
			})

			if o.initError != nil {
				return
			}

			// Initialize XML Schema validator
			var xsdHandler *xsdvalidate.XsdHandler
			xsdHandler, err = xsdvalidate.NewXsdHandlerMem(o.schemaData, xsdvalidate.ParsErrDefault)
			if err != nil {
				o.initError = fmt.Errorf("failed to create XSD handler: %v", err)
				return
			}
			o.xsdHandler = xsdHandler
		}
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
		// Try to get the appropriate type of data based on schema type
		if o.schemaType == "json" {
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
		} else if o.schemaType == "xml" {
			// Try XML request data first
			xmlReqData := txVar.Get("xml_request_body")
			if len(xmlReqData) > 0 && xmlReqData[0] != "" {
				bodyData = xmlReqData[0]
			} else {
				// Try XML response data
				xmlRespData := txVar.Get("xml_response_body")
				if len(xmlRespData) > 0 && xmlRespData[0] != "" {
					bodyData = xmlRespData[0]
				}
			}
		}

		// If we found data in TX, validate it
		if bodyData != "" {
			if o.schemaType == "json" {
				// Return true if validation fails (violation)
				return !o.isValidJSON(bodyData)
			} else if o.schemaType == "xml" {
				// Return true if validation fails (violation)
				return !o.isValidXML(bodyData)
			}
		}
	}

	// Check XML variables for raw XML content
	// For backward compatibility with the older approach
	if tx != nil && tx.Variables() != nil && o.schemaType == "xml" {
		// Try RequestXML first
		if reqXML := tx.Variables().RequestXML(); reqXML != nil {
			rawData := reqXML.Get("raw")
			if len(rawData) > 0 && rawData[0] != "" {
				// Return true if validation fails (violation)
				return !o.isValidXML(rawData[0])
			}
		}

		// Try XML (ResponseXML) next
		if respXML := tx.Variables().XML(); respXML != nil {
			rawData := respXML.Get("raw")
			if len(rawData) > 0 && rawData[0] != "" {
				// Return true if validation fails (violation)
				return !o.isValidXML(rawData[0])
			}
		}
	}

	// If no variable data found or used, try the provided data string
	if data == "" {
		return false
	}

	// Validate the provided data based on schema type
	if o.schemaType == "json" {
		// Return true if validation fails (violation)
		result := o.isValidJSON(data)
		return !result
	} else if o.schemaType == "xml" {
		// Return true if validation fails (violation)
		result := o.isValidXML(data)
		return !result
	}

	// If we don't know how to validate this schema type, return false
	return false
}

// isValidJSON performs comprehensive JSON Schema validation
func (o *validateSchema) isValidJSON(data string) bool {
	// First check basic JSON syntax
	var js interface{}
	if err := json.Unmarshal([]byte(data), &js); err != nil {
		return false
	}

	// Return true for basic validity if no schema validator is available
	if o.jsonSchema == nil {
		return true
	}

	// Use the compiled schema validator
	result := o.jsonSchema.Validate(js)
	return result == nil || result.IsValid()
}

// isValidXML performs XML validation against an XSD schema
func (o *validateSchema) isValidXML(data string) bool {
	// First check basic XML syntax
	if err := xml.Unmarshal([]byte(data), new(interface{})); err != nil {
		return false
	}

	// If no XSD handler is available, just return true for syntax validation
	if o.xsdHandler == nil {
		return true
	}

	// Validate XML against schema
	err := o.xsdHandler.ValidateMem([]byte(data), xsdvalidate.ValidErrDefault)
	return err == nil
}

func init() {
	Register("validateSchema", NewValidateSchema)
}
