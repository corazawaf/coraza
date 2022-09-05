// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

// ProcessRequest fills all transaction variables from an http.Request object
// Most implementations of Coraza will probably use http.Request objects
// so this will implement all phase 0, 1 and 2 variables
// Note: This function will stop after an interruption
// Note: Do not manually fill any request variables
func ProcessRequest(tx *corazawaf.Transaction, req *http.Request) (*types.Interruption, error) {
	var client string
	cport := 0
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	spl := strings.Split(req.RemoteAddr, ":")
	if len(spl) > 1 {
		client = strings.Join(spl[0:len(spl)-1], "")
		cport, _ = strconv.Atoi(spl[len(spl)-1])
	}
	var in *types.Interruption
	// There is no socket access in the request object so we don't know the server client or port
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	// Host will always be removed from req.Headers(), so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}
	if req.Body != nil {
		_, err := io.Copy(tx.RequestBodyBuffer, req.Body)
		if err != nil {
			return tx.Interruption, err
		}
		reader, err := tx.RequestBodyBuffer.Reader()
		if err != nil {
			return tx.Interruption, err
		}
		req.Body = io.NopCloser(reader)
	}
	return tx.ProcessRequestBody()
}
