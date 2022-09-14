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

package transformations

import "testing"

func BenchmarkB64Decode(b *testing.B) {
	tests := []string{
		"VGVzdENhc2U=",
		"P.HNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"VGVzdABDYXNl",
	}

	for _, tt := range tests {
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := base64decode(tt)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}
