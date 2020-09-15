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

package persistence

type MemoryEngine struct {
	data map[string]map[string][]string
}

func (r *MemoryEngine) Init(url string) error {
	r.data = map[string]map[string][]string{}
	return nil
}

func (r *MemoryEngine) Get(key string) map[string][]string {
	return r.data[key]
}

func (r *MemoryEngine) Set(key string, data map[string][]string) error {
	r.data[key] = data
	return nil
}
