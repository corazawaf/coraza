// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.validateSchema

package operators

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/big"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	maxRemoteSchemaBytes = 4 << 20 // 4 MiB cap for remote HTTP(S) schema $ref responses
	maxJSONNumberLen     = 320     // bounds json.Number before big.Rat parsing in jsonschema/v6
	maxJSONExponent      = 324     // bounds IEEE-754 float64 exponent range ([-324, 324]) to prevent big.Rat DoS/panics
)

// Description:
// Validates JSON request or response bodies against a JSON Schema specification.
// Automatically retrieves JSON data from TX variables (json_request_body or json_response_body)
// based on the current phase. Returns true if validation fails (schema violation).
// Built-in JSON Schema drafts (draft-04, draft-06, draft-07, 2019-09, and default 2020-12)
// resolve offline from embedded metaschemas. Any remote HTTP(S) `$ref` or custom `$schema`
// dialect URI comes exclusively from the operator-supplied schema file at rule initialization
// (never from inspected request/response payloads) and is fetched with a 10s timeout, a 4 MiB
// response limit, up to 5 redirects, and no HTTPS-to-HTTP downgrade redirects.
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
	return newValidateSchema(options, nil)
}

func newValidateSchema(options plugintypes.OperatorOptions, transport http.RoundTripper) (plugintypes.Operator, error) {
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
		return nil, fmt.Errorf("reading schema from root FS: %w", err)
	}

	compile := func() (any, error) {
		doc, err := unmarshalSafeJSON(bytes.NewReader(schemaData))
		if err != nil {
			return nil, fmt.Errorf("validating schema as JSON: %w", err)
		}
		if err := validSchemaDoc(doc, 2020, true); err != nil {
			return nil, fmt.Errorf("validating schema constraints: %w", err)
		}

		const schemaResource = "coraza:///validate-schema.json"
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertContent()
		compiler.RegisterContentMediaType(&jsonschema.MediaType{
			Name: "application/json",
			Validate: func(b []byte) error {
				var v any
				return json.Unmarshal(b, &v)
			},
			UnmarshalJSON: func(b []byte) (any, error) {
				return unmarshalSafeJSON(bytes.NewReader(b))
			},
		})
		compiler.RegisterContentMediaType(&jsonschema.MediaType{
			Name: "application/xml",
			Validate: func(b []byte) error {
				var v any
				return xml.Unmarshal(b, &v)
			},
		})
		httpLoader := &schemaHTTPClient{client: http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			// Block HTTPS-to-HTTP downgrade redirects while bounding redirect hops.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("stopped after 5 redirects")
				}
				if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
					return errors.New("refusing HTTPS-to-HTTP redirect for remote schema")
				}
				return nil
			},
		}}
		compiler.UseLoader(jsonschema.SchemeURLLoader{
			"http":  httpLoader,
			"https": httpLoader,
		})
		if err := compiler.AddResource(schemaResource, doc); err != nil {
			return nil, formatCompileSchemaError(doc, err)
		}
		schema, err := compiler.Compile(schemaResource)
		if err != nil {
			return nil, formatCompileSchemaError(doc, err)
		}
		return schema, nil
	}

	var schema any
	if transport != nil {
		schema, err = compile()
	} else {
		schema, err = memoizeDo(options.Memoizer, memoizeKey("validateSchema", string(schemaData)), compile)
	}
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

func (l *schemaHTTPClient) Load(url string) (doc any, err error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JSON schema request: %w", err)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing JSON schema request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("closing JSON schema response: %w", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching JSON schema: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteSchemaBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading JSON schema response: %w", err)
	}
	if len(body) > maxRemoteSchemaBytes {
		return nil, fmt.Errorf("fetching JSON schema: response exceeds %d byte limit", maxRemoteSchemaBytes)
	}
	doc, err = unmarshalSafeJSON(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decoding remote JSON schema: %w", err)
	}
	if err := validSchemaDoc(doc, 2020, true); err != nil {
		return nil, fmt.Errorf("validating remote JSON schema: %w", err)
	}
	return doc, nil
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

	// Decode JSON preserving exact numeric precision and rejecting trailing tokens.
	js, err := unmarshalSafeJSON(strings.NewReader(data))
	if err != nil {
		return false
	}

	// Use the compiled schema validator
	return o.jsonSchema.Validate(js) == nil
}

func unmarshalSafeJSON(r io.Reader) (any, error) {
	doc, err := jsonschema.UnmarshalJSON(r)
	if err != nil {
		return nil, err
	}
	if !validJSONNumbers(doc) {
		return nil, errors.New("numeric value out of representable range")
	}
	return doc, nil
}

// validJSONNumbers rejects JSON numbers with oversized exponents/lengths that
// would overflow float64, panic big.Rat.SetString, or cause huge allocations in jsonschema/v6.
func validJSONNumbers(v any) bool {
	switch val := v.(type) {
	case json.Number:
		return validJSONNumber(val)
	case []any:
		for _, item := range val {
			if !validJSONNumbers(item) {
				return false
			}
		}
	case map[string]any:
		for _, item := range val {
			if !validJSONNumbers(item) {
				return false
			}
		}
	}
	return true
}

func validJSONNumber(val json.Number) bool {
	s := string(val)
	if len(s) == 0 || len(s) > maxJSONNumberLen {
		return false
	}
	if idx := strings.IndexAny(s, "eE"); idx >= 0 {
		exp, err := strconv.Atoi(s[idx+1:])
		if err != nil || exp < -maxJSONExponent || exp > maxJSONExponent {
			return false
		}
	}
	f, err := val.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return false
	}
	_, ok := new(big.Rat).SetString(s)
	return ok
}

var intBoundKeywords = []string{
	"minLength", "maxLength",
	"minItems", "maxItems",
	"minProperties", "maxProperties",
	"minContains", "maxContains",
}

func draftVersionFromURL(raw string) (int, bool) {
	base, frag, _ := strings.Cut(raw, "#")
	if frag != "" {
		return 0, false
	}
	trimmed, ok := strings.CutPrefix(base, "http://")
	if !ok {
		trimmed, _ = strings.CutPrefix(base, "https://")
	}
	switch trimmed {
	case "json-schema.org/schema", "json-schema.org/draft/2020-12/schema":
		return 2020, true
	case "json-schema.org/draft/2019-09/schema":
		return 2019, true
	case "json-schema.org/draft-07/schema":
		return 7, true
	case "json-schema.org/draft-06/schema":
		return 6, true
	case "json-schema.org/draft-04/schema":
		return 4, true
	default:
		return 0, false
	}
}

func formatCompileSchemaError(doc any, err error) error {
	if customDialectURI := nonBuiltinDialectURI(doc); customDialectURI != "" {
		var (
			loadErr   *jsonschema.LoadURLError
			schemeErr *jsonschema.UnsupportedURLSchemeError
			draftErr  *jsonschema.UnsupportedDraftError
			metaErr   *jsonschema.InvalidMetaSchemaURLError
		)
		if errors.As(err, &loadErr) || errors.As(err, &schemeErr) || errors.As(err, &draftErr) || errors.As(err, &metaErr) {
			return fmt.Errorf("resolving custom $schema dialect %q (only built-in JSON Schema drafts resolve offline; custom dialects require a reachable HTTP(S) metaschema): %w", customDialectURI, err)
		}
	}
	return fmt.Errorf("compiling JSON schema: %w", err)
}

func nonBuiltinDialectURI(doc any) string {
	node, ok := doc.(map[string]any)
	if !ok {
		return ""
	}
	schemaURI, ok := node["$schema"].(string)
	if !ok || schemaURI == "" {
		return ""
	}
	if _, builtin := draftVersionFromURL(schemaURI); builtin {
		return ""
	}
	return schemaURI
}

// validSchemaDoc validates only schema-valued nodes (never literal values under
// const/enum/default/examples), rejecting:
//   - length/count keywords outside Go int range (Int64() wraps 2^64 to 0 in v6.0.3)
//   - unsupported application/yaml contentMediaType (removed with goccy/go-yaml)
//   - unrecognized contentEncoding values (only base64 is decoded in v6.0.3)
//   - contentSchema declared under pre-2019 drafts where draft-04/06/07 ignores it
func validSchemaDoc(v any, draft int, isRoot bool) error {
	node, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	if schemaURI, ok := node["$schema"].(string); ok {
		hasID := false
		if _, hasDollarID := node["$id"].(string); hasDollarID {
			hasID = true
		} else if _, hasLegacyID := node["id"].(string); hasLegacyID {
			hasID = true
		}
		if isRoot || hasID {
			if parsedDraft, builtin := draftVersionFromURL(schemaURI); builtin {
				draft = parsedDraft
			}
		}
	}
	if draft < 2019 {
		if _, hasContentSchema := node["contentSchema"]; hasContentSchema {
			return fmt.Errorf("contentSchema is not supported under JSON Schema draft-%02d (upgrade $schema to draft 2019-09/2020-12 or omit $schema to use default draft 2020-12)", draft)
		}
	}
	if ce, ok := node["contentEncoding"].(string); ok && ce != "base64" {
		return fmt.Errorf("unsupported contentEncoding %q: only \"base64\" is supported", ce)
	}
	if mt, ok := node["contentMediaType"].(string); ok && strings.EqualFold(strings.TrimSpace(strings.Split(mt, ";")[0]), "application/yaml") {
		return errors.New(`unsupported contentMediaType "application/yaml"`)
	}
	hasContains := node["contains"] != nil
	for _, kw := range intBoundKeywords {
		if (kw == "minContains" || kw == "maxContains") && !hasContains {
			continue
		}
		if num, ok := node[kw].(json.Number); ok {
			if r, ok := new(big.Rat).SetString(string(num)); ok && r.IsInt() {
				n := r.Num()
				if !n.IsInt64() || n.Int64() < 0 || n.Int64() > int64(math.MaxInt) {
					return fmt.Errorf("keyword %q value %s out of integer range", kw, num)
				}
			}
		}
	}
	for _, kw := range []string{
		"not", "if", "then", "else", "contains",
		"additionalProperties", "unevaluatedProperties", "propertyNames",
		"additionalItems", "unevaluatedItems", "contentSchema",
	} {
		if err := validSchemaDoc(node[kw], draft, false); err != nil {
			return err
		}
	}
	// items may be either a single subschema (all drafts) or an array of subschemas (draft-04/07).
	switch items := node["items"].(type) {
	case map[string]any:
		if err := validSchemaDoc(items, draft, false); err != nil {
			return err
		}
	case []any:
		for _, item := range items {
			if err := validSchemaDoc(item, draft, false); err != nil {
				return err
			}
		}
	}
	for _, kw := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		if arr, ok := node[kw].([]any); ok {
			for _, item := range arr {
				if err := validSchemaDoc(item, draft, false); err != nil {
					return err
				}
			}
		}
	}
	for _, kw := range []string{
		"properties", "patternProperties", "$defs", "definitions",
		"dependentSchemas", "dependencies",
	} {
		if m, ok := node[kw].(map[string]any); ok {
			for _, sub := range m {
				if err := validSchemaDoc(sub, draft, false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func init() {
	Register("validateSchema", NewValidateSchema)
}
