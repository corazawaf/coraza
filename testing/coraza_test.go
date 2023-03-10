// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"fmt"
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	_ "github.com/corazawaf/coraza/v3/testing/engine"
	"github.com/corazawaf/coraza/v3/testing/profile"
)

func TestEngine(t *testing.T) {
	if len(profile.Profiles) == 0 {
		t.Error("failed to find tests")
	}

	t.Logf("Loading %d profiles\n", len(profile.Profiles))
	for _, p := range profile.Profiles {
		t.Run(p.Meta.Name, func(t *testing.T) {
			tt, err := testList(t, &p)
			if err != nil {
				t.Error(err)
			}
			for _, test := range tt {
				testname := p.Tests[0].Title
				t.Run(testname, func(t *testing.T) {
					if err := test.RunPhases(); err != nil {
						t.Errorf("%s, ERROR: %s", test.Name, err)
					}

					for _, e := range test.OutputErrors() {
						debug := ""
						for _, mr := range test.transaction.MatchedRules() {
							debug += fmt.Sprintf(" %d", mr.Rule().ID())
						}
						if testing.Verbose() {
							t.Errorf("\x1b[41m ERROR \x1b[0m: %s:%s: %s, got:%s\n%s\nREQUEST:\n%s", p.Meta.Name, test.Name, e, debug, test.transaction, test.Request())
						} else {
							t.Errorf("%s: ERROR: %s", test.Name, e)
						}
					}

					for _, e := range test.OutputInterruptionErrors() {
						if testing.Verbose() {
							t.Errorf("\x1b[41m ERROR \x1b[0m: %s:%s: %s\n %s\nREQUEST:\n%s", p.Meta.Name, test.Name, e, test.transaction, test.Request())
						} else {
							t.Errorf("%s: ERROR: %s", test.Name, e)
						}
					}
				})
			}
		})
	}
}

func testList(t *testing.T, p *profile.Profile) ([]*Test, error) {
	t.Helper()
	logger := debuglog.Default().
		WithLevel(debuglog.LevelDebug).
		WithOutput(testLogOutput{t})
	var tests []*Test
	for _, test := range p.Tests {
		name := test.Title
		for _, stage := range test.Stages {
			w, err := coraza.NewWAF(coraza.NewWAFConfig().
				WithRootFS(os.DirFS("testdata")).
				WithDirectives(p.Rules).
				WithDebugLogger(logger))
			if err != nil {
				return nil, err
			}
			test := NewTest(name, w)
			test.ExpectedOutput = stage.Stage.Output
			// test.RequestAddress =
			// test.RequestPort =
			if stage.Stage.Input.URI != "" {
				test.RequestURI = stage.Stage.Input.URI
			}
			if stage.Stage.Input.Method != "" {
				test.RequestMethod = stage.Stage.Input.Method
			}
			if stage.Stage.Input.Version != "" {
				test.RequestProtocol = stage.Stage.Input.Version
			}
			if stage.Stage.Input.Headers != nil {
				test.RequestHeaders = stage.Stage.Input.Headers
			}
			if stage.Stage.Output.Headers != nil {
				test.ResponseHeaders = stage.Stage.Output.Headers
			}
			// test.ResponseHeaders = stage.Output.Headers
			test.ResponseCode = 200
			test.ResponseProtocol = "HTTP/1.1"
			test.ServerAddress = stage.Stage.Input.DestAddr
			test.ServerPort = stage.Stage.Input.Port
			if stage.Stage.Input.StopMagic {
				test.DisableMagic()
			}
			if err := test.SetEncodedRequest(stage.Stage.Input.EncodedRequest); err != nil {
				return nil, err
			}
			if err := test.SetRawRequest(stage.Stage.Input.RawRequest); err != nil {
				return nil, err
			}
			if err := test.SetRequestBody(stage.Stage.Input.Data); err != nil {
				return nil, err
			}
			if err := test.SetResponseBody(stage.Stage.Output.Data); err != nil {
				return nil, err
			}
			tests = append(tests, test)
		}
	}
	return tests, nil
}
