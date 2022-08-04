// Copyright 2022 Juan Pablo Tosso
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

package operators

// We run tests both with Go and TinyGo. TinyGo does not support the default encoding/json package so we generate
// marshalers using tinyjson. Unfortunately tinyjson does not work properly with _test.go files so we define private
// structs here instead.

// testing_tinyjson.go can be regenerated with
//
// go run github.com/CosmWasm/tinyjson/tinyjson@v0.9.0 ./operators/testing.go

//tinyjson:json
type test struct {
	Input string `json:"input"`
	Param string `json:"param"`
	Name  string `json:"name"`
	Ret   int    `json:"ret"`
	Type  string `json:"type"`
}

//tinyjson:json
type tests []test
