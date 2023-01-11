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
	"path/filepath"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var addLicenseVersion = "v1.0.0" // https://github.com/google/addlicense
var golangCILintVer = "v1.48.0"  // https://github.com/golangci/golangci-lint/releases
var gosImportsVer = "v0.1.5"     // https://github.com/rinchsan/gosimports/releases/tag/v0.1.5

var errRunGoModTidy = errors.New("go.mod/sum not formatted, commit changes")
var errNoGitDir = errors.New("no .git directory found")

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
	return sh.RunV("go", "run", fmt.Sprintf("github.com/rinchsan/gosimports/cmd/gosimports@%s", gosImportsVer),
		"-w",
		"-local",
		"github.com/corazawaf/coraza",
		".")
}

// Lint verifies code quality.
func Lint() error {
	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run"); err != nil {
		return err
	}

	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}

	if sh.Run("git", "diff", "--exit-code", "go.mod", "go.sum") != nil {
		return errRunGoModTidy
	}

	return nil
}

// Test runs all tests.
func Test() error {
	if err := sh.RunV("go", "test", "./..."); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "./examples/http-server"); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "./testing/coreruleset"); err != nil {
		return err
	}
	// Execute FTW tests with multiphase evaluation enabled as well
	if err := sh.RunV("go", "test", "-tags=coraza.rule.multiphase_evaluation", "./testing/coreruleset"); err != nil {
		return err
	}

	return nil
}

// Coverage runs tests with coverage and race detector enabled.
func Coverage() error {
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-race", "-coverprofile=build/coverage-examples.txt", "-covermode=atomic", "-coverpkg=./...", "./examples/http-server"); err != nil {
		return err
	}
	if err := sh.RunV("go", "test", "-coverprofile=build/coverage-ftw.txt", "-covermode=atomic", "-coverpkg=./...", "./testing/coreruleset"); err != nil {
		return err
	}
	// This is not actually running tests with tinygo, but with the tag that includes its code so we can calculate coverage
	// for it.
	if err := sh.RunV("go", "test", "-race", "-tags=tinygo", "-coverprofile=build/coverage-tinygo.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}

	return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")
}

// Doc runs godoc, access at http://localhost:6060
func Doc() error {
	return sh.RunV("go", "run", "golang.org/x/tools/cmd/godoc@latest", "-http=:6060")
}

// Precommit installs a git hook to run check when committing
func Precommit() error {
	if _, err := os.Stat(filepath.Join(".git", "hooks")); os.IsNotExist(err) {
		return errNoGitDir
	}

	f, err := os.ReadFile(".pre-commit.hook")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(".git", "hooks", "pre-commit"), f, 0755)
}

// Check runs lint and tests.
func Check() {
	mg.SerialDeps(Lint, Test)
}
