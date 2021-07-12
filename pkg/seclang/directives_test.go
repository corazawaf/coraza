// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seclang

import (
	"testing"

	"github.com/jptosso/coraza-waf/pkg/engine"
)

func Test_directiveSecAuditLog(t *testing.T) {
	p, _ := NewParser(engine.NewWaf())
	type args struct {
		p    *Parser
		opts string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Test nil logger", args{p, ""}, true},
		//{"Test concurrent logger", args{p, "concurrent"}, false},
		{"Test apache logger", args{p, "apache /tmp/log.log"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := directiveSecAuditLog(tt.args.p, tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("directiveSecAuditLog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
