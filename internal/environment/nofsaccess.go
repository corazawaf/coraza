// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build no_fs_access
// +build no_fs_access

package environment

import "github.com/corazawaf/coraza/v3/debuglog"

var HasAccessToFS = false

// IsDirWritable is a helper function to check if the WAF has access to the filesystem
// It is unexpected to call this function when no_fs_access build tag is enabled
func IsDirWritable(logger debuglog.Logger, dir string) error {
	panic("Unexpected call to IsDirWritable with no_fs_access build tag")
}
