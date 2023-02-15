// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/corazawaf/coraza/v3/internal/variables"
)

// VariablesCount contains the number of variables handled by the variables package
// It is used to create arrays of the correct size
const VariablesCount = variables.VariablesCount
