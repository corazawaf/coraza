// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/corazawaf/coraza/v4/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v4/internal/bodyprocessors"
)

// RegisterBodyProcessor registers a body processor
// by name. If the body processor is already registered,
// it will be overwritten
func RegisterBodyProcessor(name string, fn func() plugintypes.BodyProcessor) {
	bodyprocessors.RegisterBodyProcessor(name, fn)
}
