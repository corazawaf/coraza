// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package persistence

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var persistenceEngines = map[string]plugintypes.PersistenceEngine{}

func Register(name string, engine plugintypes.PersistenceEngine) {
	persistenceEngines[name] = engine
}

func Get(name string) (plugintypes.PersistenceEngine, error) {
	if persistenceEngines[name] == nil {
		return nil, fmt.Errorf("persistence engine %s not found", name)
	}
	return persistenceEngines[name], nil
}
