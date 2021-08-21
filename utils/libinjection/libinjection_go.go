// +build !cgo

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
package libinjection

const LIBINJECTION_CGO = false

func IsSQLi(statement string) (bool, string) {
	// function is disabled
	return false, ""
}

func IsXSS(input string) bool {
	// function is disabled
	return false
}
