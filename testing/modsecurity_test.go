// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build modsecurity

// This file runs benchmarks against ModSecurity. ModSecurity must be installed to be able to
// run these benchmarks.
//
// ModSecurity can be installed on MacOS using HomeBrew:
//
//	brew tap anuraaga/go-modsecurity https://github.com/anuraaga/go-modsecurity.git
//	brew install modsecurity
//
// The benchmarks require a build tag and cgo flags to run.
//
//	CGO_CFLAGS=$(pkg-config --cflags modsecurity) CGO_LDFLAGS=$(pkg-config --libs modsecurity) go test -bench . ./testing -tags modsecurity

package testing

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anuraaga/go-modsecurity"
)

func BenchmarkModSecurityCRSCompilation(b *testing.B) {
	files := []string{
		"../coraza.conf-recommended",
		filepath.Join(crspath, "crs-setup.conf.example"),
	}
	r, err := filepath.Glob(filepath.Join(crspath, "rules", "*.conf"))
	require.NoError(b, err)
	files = append(files, r...)
	for i := 0; i < b.N; i++ {
		ms, err := modsecurity.NewModsecurity()
		require.NoError(b, err)
		ms.SetServerLogCallback(func(msg string) {
			fmt.Println(msg)
		})
		rs := ms.NewRuleSet()
		for _, f := range files {
			err = rs.AddFile(f)
			require.NoError(b, err)
		}
	}
}

func BenchmarkModSecurityCRSSimpleGET(b *testing.B) {
	ms, rs, err := crsMS()
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		tx, err := rs.NewTransaction("127.0.0.1", 8080, "127.0.0.1", 8080)
		require.NoError(b, err)
		err = tx.ProcessUri("/some_path/with?parameters=and&other=Stuff", "GET", "1.1")
		require.NoError(b, err)
		err = tx.AddRequestHeader("Host", "localhost")
		require.NoError(b, err)
		err = tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		require.NoError(b, err)
		err = tx.AddRequestHeader("Accept", "application/json")
		require.NoError(b, err)
		err = tx.ProcessRequestHeaders()
		require.NoError(b, err)
		err = tx.ProcessRequestBody()
		require.NoError(b, err)
		err = tx.AddResponseHeader("Content-Type", "application/json")
		require.NoError(b, err)
		err = tx.ProcessResponseHeaders(200, "1.1")
		require.NoError(b, err)
		err = tx.ProcessResponseBody()
		require.NoError(b, err)
		err = tx.ProcessLogging()
		require.NoError(b, err)
		tx.Cleanup()
	}
	runtime.KeepAlive(ms)
}

func BenchmarkModSecurityCRSSimplePOST(b *testing.B) {
	ms, rs, err := crsMS()
	require.NoError(b, err)
	for i := 0; i < b.N; i++ {
		tx, err := rs.NewTransaction("127.0.0.1", 8080, "127.0.0.1", 8080)
		require.NoError(b, err)
		err = tx.ProcessUri("/some_path/with?parameters=and&other=Stuff", "POST", "1.1")
		require.NoError(b, err)
		err = tx.AddRequestHeader("Host", "localhost")
		require.NoError(b, err)
		err = tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36")
		require.NoError(b, err)
		err = tx.AddRequestHeader("Accept", "application/json")
		require.NoError(b, err)
		err = tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(b, err)
		body := []byte("parameters2=and&other2=Stuff")

		err = tx.AddRequestHeader("Content-Length", strconv.Itoa(len(body)))
		require.NoError(b, err)
		err = tx.ProcessRequestHeaders()
		require.NoError(b, err)
		err = tx.ReadRequestBodyFrom(body)
		require.NoError(b, err)
		err = tx.ProcessRequestBody()
		require.NoError(b, err)
		err = tx.AddResponseHeader("Content-Type", "application/json")
		require.NoError(b, err)
		err = tx.ProcessResponseHeaders(200, "1.1")
		require.NoError(b, err)
		err = tx.ProcessResponseBody()
		require.NoError(b, err)
		err = tx.ProcessLogging()
		require.NoError(b, err)
		tx.Cleanup()
	}
	runtime.KeepAlive(ms)
}

func crsMS() (*modsecurity.Modsecurity, *modsecurity.RuleSet, error) {
	files := []string{
		"../coraza.conf-recommended",
		filepath.Join(crspath, "crs-setup.conf.example"),
	}
	r, err := filepath.Glob(filepath.Join(crspath, "rules", "*.conf"))
	if err != nil {
		return nil, nil, err
	}
	files = append(files, r...)
	ms, err := modsecurity.NewModsecurity()
	if err != nil {
		return nil, nil, err
	}
	ms.SetServerLogCallback(func(msg string) {
		fmt.Println(msg)
	})
	rs := ms.NewRuleSet()
	for _, f := range files {
		err = rs.AddFile(f)
		if err != nil {
			return nil, nil, err
		}
	}

	return ms, rs, nil
}
