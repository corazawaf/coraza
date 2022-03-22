// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http:// www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seclang

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/corazawaf/coraza/v2/types"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v2"
	"go.uber.org/zap"
)

// Parser provides functions to evaluate (compile) SecLang directives
type Parser struct {
	options     *DirectiveOptions
	currentLine int
	currentFile string
	currentDir  string
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
		files, err = filepath.Glob(profilePath)
		if err != nil {
			return err
		}
	} else {
		files = append(files, profilePath)
	}
	for _, profilePath := range files {
		p.currentFile = profilePath
		p.currentDir = filepath.Dir(profilePath)
		file, err := os.ReadFile(profilePath)
		if err != nil {
			p.options.Waf.Logger.Error(err.Error(),
				zap.String("path", profilePath),
			)
			return err
		}

		err = p.FromString(string(file))
		if err != nil {
			p.options.Waf.Logger.Error(err.Error(),
				zap.String("path", profilePath),
			)
			return err
		}
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
	for scanner.Scan() {
		p.currentLine++
		line := scanner.Text()
		linebuffer += strings.TrimSpace(line)
		// Check if line ends with \
		match := pattern.MatchString(line)
		if !match {
			err := p.evaluate(linebuffer)
			if err != nil {
				return err
			}
			linebuffer = ""
		} else {
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
	p.options.Waf.Logger.Debug("parsing directive",
		zap.String("directive", data),
	)
	directive := spl[0]

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"' {
		opts = strings.Trim(opts, `"`)
	}

	d, ok := directivesMap[strings.ToLower(directive)]
	if !ok || d == nil {
		return p.log("Unsupported directive " + directive)
	}

	p.options.Opts = opts
	p.options.Config.Set("last_profile_line", p.currentLine)
	p.options.Config.Set("parser_config_file", p.currentFile)
	p.options.Config.Set("parser_config_dir", p.currentDir)
	return d(p.options)
}

func (p *Parser) log(msg string) error {
	msg = fmt.Sprintf("[Parser] [Line %d] %s", p.currentLine, msg)
	p.options.Waf.Logger.Error(msg,
		zap.Int("line", p.currentLine),
	)
	return errors.New(msg)
}

// SetCurrentDir forces the current directory of the parser to dir
// If FromFile was used, the file directory will be used instead unless
// overwritten by this function
// It is mostly used by operators that consumes relative paths
func (p *Parser) SetCurrentDir(dir string) {
	p.currentDir = dir
}

// NewParser creates a new parser from a WAF instance
// Rules and settings will be inserted into the WAF
// rule container (RuleGroup).
func NewParser(waf *coraza.Waf) (*Parser, error) {
	if waf == nil {
		return nil, errors.New("must use a valid waf instance")
	}
	p := &Parser{
		options: &DirectiveOptions{
			Waf:    waf,
			Config: make(types.Config),
		},
	}
	return p, nil
}
