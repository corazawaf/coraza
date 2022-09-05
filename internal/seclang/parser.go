// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/io"
	"github.com/corazawaf/coraza/v3/types"
)

// maxIncludeRecursion is used to avoid DDOS by including files that include
const maxIncludeRecursion = 100

// Parser provides functions to evaluate (compile) SecLang directives
type Parser struct {
	options      *DirectiveOptions
	currentLine  int
	currentFile  string
	currentDir   string
	root         fs.FS
	includeCount int
}

// FromFile imports directives from a file
// It will return error if any directive fails to parse
// or the file does not exist.
// If the path contains a *, it will be expanded to all
// files in the directory matching the pattern
func (p *Parser) FromFile(profilePath string) error {
	files := []string{}
	if strings.Contains(profilePath, "*") {
		var err error
		files, err = fs.Glob(p.root, profilePath)
		if err != nil {
			return err
		}
	} else {
		files = append(files, profilePath)
	}
	for _, profilePath := range files {
		profilePath = strings.TrimSpace(profilePath)
		if !strings.HasPrefix(profilePath, "/") {
			profilePath = filepath.Join(p.currentDir, profilePath)
		}
		p.currentFile = profilePath
		lastDir := p.currentDir
		p.currentDir = filepath.Dir(profilePath)
		file, err := fs.ReadFile(p.root, profilePath)
		if err != nil {
			p.options.WAF.Logger.Error(err.Error())
			return err
		}

		err = p.FromString(string(file))
		if err != nil {
			p.options.WAF.Logger.Error(err.Error())
			return err
		}
		// restore the lastDir post processing all includes
		p.currentDir = lastDir
	}
	return nil
}

// FromString imports directives from a string
// It will return error if any directive fails to parse
// or arguments are invalid
func (p *Parser) FromString(data string) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var linebuffer = ""
	pattern := regexp.MustCompile(`\\(\s+)?$`)
	inQuotes := false
	for scanner.Scan() {
		p.currentLine++
		line := strings.TrimSpace(scanner.Text())
		if !inQuotes && len(line) > 0 && line[len(line)-1] == '`' {
			inQuotes = true
		} else if inQuotes && len(line) > 0 && line[0] == '`' {
			inQuotes = false
		}
		if inQuotes {
			linebuffer += line + "\n"
		} else {
			linebuffer += line
		}

		// Check if line ends with \
		if !pattern.MatchString(line) && !inQuotes {
			err := p.evaluate(linebuffer)
			if err != nil {
				return err
			}
			linebuffer = ""
		} else if !inQuotes {
			linebuffer = strings.TrimSuffix(linebuffer, "\\")
		}
	}
	return nil
}

func (p *Parser) evaluate(data string) error {
	if data == "" || data[0] == '#' {
		return nil
	}
	// first we get the directive
	spl := strings.SplitN(data, " ", 2)
	opts := ""
	if len(spl) == 2 {
		opts = spl[1]
	}
	p.options.WAF.Logger.Debug("parsing directive %q", data)
	directive := spl[0]

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"' {
		opts = strings.Trim(opts, `"`)
	}
	directive = strings.ToLower(directive)
	if directive == "include" {
		// this is a special hardcoded case
		// we cannot add it as a directive type because there are recursion issues
		// note a user might still include another file that includes the original file
		// generating a DDOS attack
		if p.includeCount >= maxIncludeRecursion {
			return fmt.Errorf("cannot include more than %d files", maxIncludeRecursion)
		}
		p.includeCount++
		return p.FromFile(opts)
	}
	d, ok := directivesMap[directive]
	if !ok || d == nil {
		return p.log("Unsupported directive " + directive)
	}

	p.options.Opts = opts
	p.options.Config.Set("last_profile_line", p.currentLine)
	p.options.Config.Set("parser_config_file", p.currentFile)
	p.options.Config.Set("parser_config_dir", p.currentDir)
	p.options.Config.Set("parser_root", p.root)
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	p.options.Config.Set("working_dir", wd)

	return d(p.options)
}

func (p *Parser) log(msg string) error {
	msg = fmt.Sprintf("[Parser] [Line %d] %s", p.currentLine, msg)
	p.options.WAF.Logger.Error("[%d] %s", p.currentLine, msg)
	return errors.New(msg)
}

// SetCurrentDir forces the current directory of the parser to dir
// If FromFile was used, the file directory will be used instead unless
// overwritten by this function
// It is mostly used by operators that consumes relative paths
func (p *Parser) SetCurrentDir(dir string) {
	p.currentDir = dir
}

// SetRoot sets the root of the filesystem for resolving paths. If not set, the OS's
// filesystem is used. SetRoot with `embed.FS` can allow parsing Include and FromFile
// directives for an embedded set of rules, or zip.Reader can be used to work with
// an archive.
func (p *Parser) SetRoot(root fs.FS) {
	p.root = root
}

// NewParser creates a new parser from a WAF instance
// Rules and settings will be inserted into the WAF
// rule container (RuleGroup).
func NewParser(waf *corazawaf.WAF) *Parser {
	p := &Parser{
		options: &DirectiveOptions{
			WAF:      waf,
			Config:   make(types.Config),
			Datasets: make(map[string][]string),
		},
		root: io.OSFS{},
	}
	return p
}
