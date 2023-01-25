// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"io"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/rules"
	"github.com/corazawaf/coraza/v3/types"
)

type prependFn struct {
	data macro.Macro
}

func (a *prependFn) Init(r rules.RuleMetadata, data string) error {
	m, err := macro.NewMacro(data)
	if err != nil {
		return err
	}
	a.data = m
	return nil
}

func (a *prependFn) Evaluate(r rules.RuleMetadata, txS rules.TransactionState) {
	// TODO(anuraaga): This is quite complicated. Evaluate whether plugin API needs to support this.
	tx := txS.(*corazawaf.Transaction)
	if !tx.WAF.ContentInjection {
		tx.WAF.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := a.data.Expand(tx)
	buf := corazawaf.NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     tx.WAF.TmpDir,
		MemoryLimit: tx.WAF.ResponseBodyLimit,
		Limit:       tx.WAF.ResponseBodyLimit,
	})

	_, err := buf.Write([]byte(data))
	if err != nil {
		tx.WAF.Logger.Debug("failed to write buffer while evaluating prepend action: %s", err.Error())
	}
	reader, err := tx.ResponseBodyReader()
	if err != nil {
		tx.WAF.Logger.Debug("failed to read response body while evaluating prepend action: %s", err.Error())
	}
	_, err = io.Copy(buf, reader)
	if err != nil {
		tx.WAF.Logger.Debug("failed to append response buffer while evaluating prepend action: %s", err.Error())
	}
	// TODO: elaborate on ContentInjection actions considering that the WAF may NOT buffer the whole response
	// We overwrite the response body buffer with the new buffer
	// TODO: implement the swap
	// *tx.ResponseBodyBuffer = *buf

	// Maybe in the future we could add the prepend function to the BodyBuffer
}

func (a *prependFn) Type() rules.ActionType {
	return rules.ActionTypeNondisruptive
}

func prepend() rules.Action {
	return &prependFn{}
}

var (
	_ rules.Action      = &prependFn{}
	_ ruleActionWrapper = prepend
)
