// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo
// +build !tinygo

// Note: The following code has been extracted from https://github.com/coreruleset/albedo/blob/main/server/server.go
// TODO: Make it possible to import albedo.
package coreruleset

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
)

type reflectionSpec struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	EncodedBody string            `json:"encodedBody"`
	LogMessage  string            `json:"logMessage"`
}

func handleReflect(t testing.TB, w http.ResponseWriter, r *http.Request) {
	log.Println("Received reflection request")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("Failed to parse request body"))
		if err != nil {
			log.Printf("Failed to write response body: %s", err.Error())
		}
		log.Println("Failed to parse request body")
		return
	}
	spec := &reflectionSpec{}
	if err = json.Unmarshal(body, spec); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("Invalid JSON in request body"))
		if err != nil {
			log.Printf("Failed to write response body: %s", err.Error())
		}
		log.Println("Invalid JSON in request body")
		return
	}

	if spec.LogMessage != "" {
		log.Println(spec.LogMessage)
	}

	for name, value := range spec.Headers {
		log.Printf("Reflecting header '%s':'%s'", name, value)
		w.Header().Add(name, value)
	}

	if spec.Status > 0 && spec.Status < 100 || spec.Status >= 600 {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Invalid status code: %d", spec.Status)))
		if err != nil {
			log.Printf("Failed to write response body: %s", err.Error())
		}
		log.Printf("Invalid status code: %d", spec.Status)
		return
	}
	status := spec.Status
	if status == 0 {
		status = http.StatusOK
	}
	log.Printf("Reflecting status '%d'", status)
	w.WriteHeader(status)

	responseBody, err := decodeBody(t, spec)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Printf("Failed to write response body: %s", err.Error())
		}
		log.Println(err.Error())
		return
	}

	if responseBody == "" {
		return
	}

	responseBodyBytes := []byte(responseBody)
	if len(responseBody) > 200 {
		responseBody = responseBody[:min(len(responseBody), 200)] + "..."
	}
	log.Printf("Reflecting body '%s'", responseBody)
	_, err = w.Write(responseBodyBytes)
	if err != nil {
		log.Printf("Failed to write response body: %s", err.Error())
	}
}

func decodeBody(t testing.TB, spec *reflectionSpec) (string, error) {
	t.Helper()
	if spec.Body != "" {
		return spec.Body, nil
	}

	if spec.EncodedBody == "" {
		return "", nil
	}

	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(spec.EncodedBody))
	bodyBytes, err := io.ReadAll(decoder)
	if err != nil {
		return "", errors.New("invalid base64 encoding of response body")

	}
	return string(bodyBytes), nil
}
