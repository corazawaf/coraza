// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var addLicenseVersion = "v1.0.0" // https://github.com/google/addlicense
var golangCILintVer = "v1.48.0"  // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.1.5"     // https://github.com/rinchsan/gosimports/releases/tag/v0.1.5

var errCommitFormatting = errors.New("files not formatted, please commit formatting changes")

// Format formats code in this repository.
func Format() error {
	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}
	// addlicense strangely logs skipped files to stderr despite not being erroneous, so use the long sh.Exec form to
	// discard stderr too.
	if _, err := sh.Exec(map[string]string{}, io.Discard, io.Discard, "go", "run", fmt.Sprintf("github.com/google/addlicense@%s", addLicenseVersion),
		"-c", "Juan Pablo Tosso and the OWASP Coraza contributors",
		"-s=only",
		"-ignore", "**/*.yml",
		"-ignore", "**/*.yaml",
		"-ignore", "examples/**", "."); err != nil {
		return err
	}
	return sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer), "-w", ".")
}

// Lint verifies code quality.
func Lint() error {
	mg.SerialDeps(Format)

	if sh.Run("git", "diff", "--exit-code") != nil {
		return errCommitFormatting
	}

	return sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run")
}

// Test runs all tests.
func Test() error {
	return sh.RunV("go", "test", "./...")
}

// Coverage runs tests with coverage and race detector enabled.
func Coverage() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}

	return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")
}

// Doc runs godoc, access at http://localhost:6060
func Doc() error {
	return sh.RunV("go", "run", "golang.org/x/tools/cmd/godoc@latest", "-http=:6060")
}

// Check runs tests and lint.
func Check() {
	mg.SerialDeps(Test, Lint)
}
