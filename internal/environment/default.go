// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo.wasm && (!js || !wasm)
// +build !tinygo.wasm
// +build !js !wasm

package environment

// HasAccessToFS indicates whether the build environment is TinyGo.
var HasAccessToFS = true
