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

package loggers

import "testing"

func TestDefaultWriters(t *testing.T) {
	ws := []string{"serial", "concurrent"}
	for _, writer := range ws {
		if w, err := getLogWriter(writer); err != nil {
			t.Error(err)
		} else if w == nil {
			t.Errorf("invalid %s writer", writer)
		}
	}

}
func TestWriterPlugins(t *testing.T) {

}

func TestDefaultAuditLogger(t *testing.T) {
	al, err := NewAuditLogger()
	if err != nil {
		t.Error(err)
	}
	log := AuditLog{}
	if err := al.Write(log); err != nil {
		t.Error(err)
	}
}
