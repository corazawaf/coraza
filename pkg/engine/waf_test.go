// Copyright 2020 Juan Pablo Tosso
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

package engine

import (
	"testing"
)

var waf *Waf

func TestWAFInitialize(t *testing.T) {
	waf = &Waf{}
	waf.Init()
	if waf.Rules == nil {
		t.Error("Failed to initialize rule groups")
	}
}

func TestGeoIP(t *testing.T) {
	w := NewWaf()
	err := w.InitGeoip("")
	if err == nil {
		t.Error("Invalid geoip location shouldnt work")
	}
}

func TestPersistenceInit(t *testing.T) {
	w := NewWaf()

	err := w.InitPersistenceEngine()
	if err != nil {
		t.Error("Failed to init persistence engine")
	}
}

func TestNewTransaction(t *testing.T) {

}
