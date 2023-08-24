// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

// Transformation is used to create transformation plugins
// See the documentation for more information
// If a transformation fails to run it will return the same string
// and an error, errors are only used for logging, it won't stop
// the execution of the rule
// "updated" is used for transformation cache, if true, the cache
// will be updated
type Transformation = func(input string) (result string, updated bool, err error)
