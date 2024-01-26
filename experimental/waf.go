// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"context"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

type Option func(*corazawaf.Options)

// WithID sets the transaction ID
func WithID(id string) Option {
	return func(o *corazawaf.Options) {
		o.ID = strings.TrimSpace(id)
	}
}

// WithContext sets the transaction context, this is useful for passing
// a context into the logger.
// The transaction lifecycle isn't tied to the context lifecycle.
func WithContext(ctx context.Context) Option {
	return func(o *corazawaf.Options) {
		o.Context = ctx
	}
}

// WAFWithOptions is an interface that allows to create transactions
// with options
type WAFWithOptions interface {
	NewTransactionWithOptions(opts ...Option) types.Transaction
}
