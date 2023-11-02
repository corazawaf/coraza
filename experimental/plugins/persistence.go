// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/persistence"
)

// RegisterPersistenceEngine registers a new persistence engine
func RegisterPersistenceEngine(name string, engine plugintypes.PersistenceEngine) {
	persistence.Register(name, engine)
}
