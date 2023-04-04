// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type bodyProcessorWrapper = func() plugintypes.BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

// RegisterBodyProcessor registers a body processor
// by name. If the body processor is already registered,
// it will be overwritten
func RegisterBodyProcessor(name string, fn func() plugintypes.BodyProcessor) {
	processors[name] = fn
}

// GetBodyProcessor returns a body processor by name
// If the body processor is not found, it returns an error
func GetBodyProcessor(name string) (plugintypes.BodyProcessor, error) {
	if fn, ok := processors[strings.ToLower(name)]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}
