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

package utils

import (
	"context"
	"crypto/rand"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const randomchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var Ctx = context.Background()
var mu sync.Mutex

func RandomString(length int) string {
	bytes := make([]byte, length)
	//There is an entropy bug here with a lot of concurrency, so we need sync

	mu.Lock()
	_, err := rand.Read(bytes)
	mu.Unlock()
	if err != nil {
		// is it ok?
		return RandomString(length)
	}

	for i, b := range bytes {
		bytes[i] = randomchars[b%byte(len(randomchars))]
	}
	return string(bytes)
}

func TrimLeftChars(s string, n int) string {
	m := 0
	for i := range s {
		if m >= n {
			return s[i:]
		}
		m++
	}
	return s[:0]
}

func RemoveQuotes(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSuffix(s, `"`)
	s = strings.TrimPrefix(s, `"`)
	s = strings.TrimSuffix(s, `'`)
	s = strings.TrimPrefix(s, `'`)
	return s
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func ArrayContains(arr []string, search string) bool {
	for _, v := range arr {
		if v == search {
			return true
		}
	}
	return false
}

func ArrayContainsInt(arr []int, search int) bool {
	for _, v := range arr {
		if v == search {
			return true
		}
	}
	return false
}

func OpenFile(path string) ([]byte, error) {
	var ret []byte
	if strings.HasPrefix(path, "https://") {
		client := &http.Client{
			Timeout: time.Second * 15,
		}
		req, _ := http.NewRequest("GET", path, nil)
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		ret, _ = ioutil.ReadAll(res.Body)
	} else {
		var err error
		ret, err = ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
