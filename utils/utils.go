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

package utils

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func IntInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func OpenFile(path string, key string) ([]byte, error) {
	if strings.HasPrefix(path, "https://") {
		return nil, fmt.Errorf("not implemented")
	} else {
		return ioutil.ReadFile(path)
	}
}

func ArgsToMap(args string) map[string]string {
	a := map[string]string{}
	re := regexp.MustCompile(`([\w\-_]+)=(.*?(?:\s|$))`)
	for _, data := range re.FindAllStringSubmatch(args, -1) {
		a[strings.TrimSpace(data[1])] = strings.TrimSpace(data[2])
	}
	return a
}
