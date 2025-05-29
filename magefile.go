// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build mage
// +build mage

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var addLicenseVersion = "v1.1.1" // https://github.com/google/addlicense/releases
var gosImportsVer = "v0.3.7"     // https://github.com/rinchsan/gosimports/releases
var golangCILintVer = "v1.64.8"  // https://github.com/golangci/golangci-lint/releases
var errNoGitDir = errors.New("no .git directory found")
var errUpdateGeneratedFiles = errors.New("generated files need to be updated")

// Format formats code in this repository.
func Format() error {
	if err := sh.RunV("go", "generate", "./..."); err != nil {
		return err
	}

	if err := sh.RunV("go", "mod", "tidy"); err != nil {
		return err
	}

	if err := sh.RunV("go", "work", "sync"); err != nil {
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
	if err := sh.RunV("go", "generate", "./..."); err != nil {
		return err
	}

	if sh.Run("git", "diff", "--exit-code", "--", "'*.gen.go'") != nil {
		return errUpdateGeneratedFiles
	}

	if err := sh.RunV("go", "run", fmt.Sprintf("github.com/golangci/golangci-lint/cmd/golangci-lint@%s", golangCILintVer), "run"); err != nil {
		return err
	}

	if err := sh.RunV("go", "work", "sync"); err != nil {
		return err
	}

	if err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
			cmd := exec.Command("go", "mod", "tidy")
			cmd.Dir = path
			out, err := cmd.CombinedOutput()
			fmt.Printf(string(out))
			if err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// Test runs all tests.
func Test() error {
	if err := sh.RunV("go", "test", "./..."); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "-tags=memoize_builders", "./..."); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "./examples/http-server", "-race"); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "./testing/coreruleset"); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "-tags=memoize_builders", "./testing/coreruleset"); err != nil {
		return err
	}

	// Execute FTW tests with multiphase evaluation enabled as well
	if err := sh.RunV("go", "test", "-tags=coraza.rule.multiphase_evaluation", "./testing/coreruleset"); err != nil {
		return err
	}

	// Execute FTW tests with coraza.rule.no_regex_multiline as well
	if err := sh.RunV("go", "test", "-tags=coraza.rule.no_regex_multiline", "./testing/coreruleset"); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "-tags=coraza.rule.no_regex_multiline", "-run=^TestRx", "./..."); err != nil {
		return err
	}

	if err := sh.RunV("go", "test", "-tags=coraza.rule.case_sensitive_args_keys", "-run=^TestCaseSensitive", "./..."); err != nil {
		return err
	}

	return nil
}

func buildTagsFlags(tags string) string {
	if tags == "" {
		return ""
	}
	// we remove all non alphanumeric _,-
	rx := regexp.MustCompile("^[\\w_,\\.]+$")
	if !rx.MatchString(tags) {
		panic("Invalid build tags")
	}
	return tags
}

// Coverage runs tests with coverage and race detector enabled.
// Usage: mage coverage [buildTags]
func Coverage() error {
	buildTags := os.Getenv("BUILD_TAGS")
	tags := buildTagsFlags(buildTags)
	if err := os.MkdirAll("build", 0755); err != nil {
		return err
	}
	fmt.Println("Running tests with coverage")
	fmt.Println("Tags:", tags)
	tagsCmd := ""
	if tags != "" {
		tagsCmd = "-tags=" + tags
	}
	if err := sh.RunV("go", "test", "-race", tagsCmd, "-coverprofile=build/coverage.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
		return err
	}
	// Execute http-server tests with coverage
	if err := sh.RunV("go", "test", "-race", tagsCmd, "-coverprofile=build/coverage-examples.txt", "-covermode=atomic", "-coverpkg=./...", "./examples/http-server"); err != nil {
		return err
	}
	// Execute FTW tests with coverage as well
	if err := sh.RunV("go", "test", tagsCmd, "-coverprofile=build/coverage-ftw.txt", "-covermode=atomic", "-coverpkg=./...", "./testing/coreruleset"); err != nil {
		return err
	}
	// we run tinygo tag only if memoize_builders is not enabled
	if !strings.Contains(tags, "memoize_builders") {
		if tagsCmd != "" {
			tagsCmd += ",tinygo"
		}
		if err := sh.RunV("go", "test", "-race", tagsCmd, "-coverprofile=build/coverage-tinygo.txt", "-covermode=atomic", "-coverpkg=./...", "./..."); err != nil {
			return err
		}
	}

	return sh.RunV("go", "tool", "cover", "-html=build/coverage.txt", "-o", "build/coverage.html")
}

// Fuzz runs fuzz tests
func Fuzz() error {
	// Go must be run once per test when fuzzing
	tests := []struct {
		pkg   string
		tests []string
	}{
		{
			pkg: "./internal/operators",
			tests: []string{
				"FuzzSQLi",
				"FuzzXSS",
			},
		},
		{
			pkg: "./internal/transformations",
			tests: []string{
				"FuzzB64Decode$",
				"FuzzB64DecodeExt",
				"FuzzCMDLine",
			},
		},
	}

	for _, pkgTests := range tests {
		for _, test := range pkgTests.tests {
			fmt.Println("Running", test)
			if err := sh.RunV("go", "test", "-fuzz="+test, "-fuzztime=2m", pkgTests.pkg); err != nil {
				return err
			}
		}
	}

	return nil
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

// combinations generates all possible combinations of build tags
func combinations(tags []string) []string {
	var result []string
	n := len(tags)
	for i := 0; i < (1 << n); i++ {
		var combo []string
		for j := 0; j < n; j++ {
			if i&(1<<j) != 0 {
				combo = append(combo, tags[j])
			}
		}
		if len(combo) > 0 {
			result = append(result, strings.Join(combo, ","))
		} else {
			result = append(result, "")
		}
	}
	return result
}

// Generates a JSON output to stdout which contains all permutations of build tags for the project.
func TagsMatrix() error {
	tags := []string{
		"coraza.rule.case_sensitive_args_keys",
		"coraza.rule.no_regex_multiline",
		"memoize_builders",
		"coraza.rule.multiphase_evaluation",
		"no_fs_access",
	}
	combos := combinations(tags)

	jsonData, err := json.Marshal(combos)
	if err != nil {
		fmt.Println("Error generating JSON:", err)
		return nil
	}

	fmt.Println(string(jsonData))
	return nil
}
