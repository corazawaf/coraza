// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"io"

	"github.com/corazawaf/coraza/v3/types"
)

type prependFn struct {
	data corazawaf.Macro
}

func (a *prependFn) Init(r *corazawaf.Rule, data string) error {
	macro, err := corazawaf.NewMacro(data)
	if err != nil {
		return err
	}
	a.data = *macro
	return nil
}

func (a *prependFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	if !tx.WAF.ContentInjection {
		tx.WAF.Logger.Debug("append rejected because of ContentInjection")
		return
	}
	data := a.data.Expand(tx)
	buf := corazawaf.NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     tx.WAF.TmpDir,
		MemoryLimit: tx.WAF.RequestBodyInMemoryLimit,
	})

	_, err := buf.Write([]byte(data))
	if err != nil {
		tx.WAF.Logger.Debug("failed to write buffer while evaluating prepend action")
	}
	reader, err := tx.ResponseBodyBuffer.Reader()
	if err != nil {
		tx.WAF.Logger.Debug("failed to read response body while evaluating prepend action")
	}
	_, err = io.Copy(buf, reader)
	if err != nil {
		tx.WAF.Logger.Debug("failed to append response buffer while evaluating prepend action")
	}
	// We overwrite the response body buffer with the new buffer
	*tx.ResponseBodyBuffer = *buf
	// Maybe in the future we could add the prepend function to the BodyBuffer
}

func (a *prependFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func prepend() corazawaf.RuleAction {
	return &prependFn{}
}

var (
	_ corazawaf.RuleAction = &prependFn{}
	_ ruleActionWrapper    = prepend
)
