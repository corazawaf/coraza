// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package persistence

import "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"

var persistenceEngines = map[string]plugintypes.PersistenceEngine{}

func RegisterPersistenceEngine(name string, engine plugintypes.PersistenceEngine) {
	persistenceEngines[name] = engine
}

func GetPersistenceEngine(name string) plugintypes.PersistenceEngine {
	return persistenceEngines[name]
}
