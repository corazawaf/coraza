// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !no_fs_access
// +build !no_fs_access

package environment

// HasAccessToFS indicates whether the runtime target environment has access
// to OS' filesystem or not.
var HasAccessToFS = true
