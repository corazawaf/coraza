// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package io

import (
	"io/fs"
)

// FSReadFile wraps fs.ReadFile supporting embedio on windows
var FSReadFile = fs.ReadFile
