// Copyright 2020 Juan Pablo Tosso
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

package main

import (
	"context"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/serve"
	"io"
	"net/http"
)

type CorazaSpec struct{}

type CorazaFilter struct {
	//constant values
	policypath  string
	wafinstance *engine.Waf
}

func (s *CorazaSpec) Name() string { return "corazaWAF" }

func (s *CorazaSpec) CreateFilter(config []interface{}) (filters.Filter, error) {
	if len(config) == 0 {
		return nil, filters.ErrInvalidFilterParameters
	}
	policypath := config[0].(string)

	if policypath == "" {
		return nil, filters.ErrInvalidFilterParameters
	}

	wi := &engine.Waf{}
	wi.Init()

	wafparser := parser.Parser{}
	wafparser.Init(wi)
	err := wafparser.FromFile(policypath)
	if err != nil {
		return nil, err
	}
	wi.Rules.Sort()
	wi.InitLogger()
	return &CorazaFilter{policypath, wi}, nil
}

func (f *CorazaFilter) Request(ctx filters.FilterContext) {
	tx := f.wafinstance.NewTransaction()
	req := ctx.Request()
	*req = *(req.WithContext(context.WithValue(req.Context(), "tx", tx)))

	err := tx.ParseRequestObjectHeaders(req)
	if err != nil || tx.ExecutePhase(1) {
		f.ErrorPage(ctx)
		return
	}

	err = tx.ParseRequestObjectBody(req)
	if err != nil || tx.ExecutePhase(2) {
		f.ErrorPage(ctx)
		return
	}
}

func (f *CorazaFilter) Response(ctx filters.FilterContext) {
	res := ctx.Response()
	tx := f.GetTransaction(ctx)
	err := tx.ParseResponseObject(res)
	if err != nil || tx.Disrupted {
		f.ErrorPage(ctx)
		return
	}
	tx.ExecutePhase(5)
}

func (f *CorazaFilter) ErrorPage(ctx filters.FilterContext) {
	tx := f.GetTransaction(ctx)
	serve.ServeHTTP(ctx, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		//rw.Header().Set("Content-Type", "text/html")
		io.WriteString(rw, tx.GetErrorPage())
	}))
}

func (f *CorazaFilter) GetTransaction(ctx filters.FilterContext) *engine.Transaction {
	req := ctx.Request()
	return req.Context().Value("tx").(*engine.Transaction)
}
