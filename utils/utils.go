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
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const randomchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var Ctx = context.Background()
var mu sync.Mutex

func RandomString(length int) string {
	bytes := make([]byte, length)
	//There is an entropy bug here with a lot of concurrency, so we need sync

	mu.Lock()
	_, err := rand.Read(bytes)
	mu.Unlock()
	if err != nil {
		// TODO is it ok?
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

func IntInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func OpenFile(path string, allowRemote bool, key string) ([]byte, error) {
	if strings.HasPrefix(path, "https://") {
		if !allowRemote {
			return []byte{}, fmt.Errorf("remote resources are not allowed")
		}
		client := &http.Client{
			Timeout: time.Second * 15,
		}
		req, _ := http.NewRequest("GET", path, nil)
		req.Header.Add("Coraza-key", key)
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		return io.ReadAll(res.Body)
	} else {
		return ioutil.ReadFile(path)
	}
}

func IsDigit(x byte) bool {
	return (x >= '0') && (x <= '9')
}

func ArgsToMap(args string) map[string]string {
	a := map[string]string{}
	re := regexp.MustCompile(`([\w\-_]+)=(.*?(?:\s|$))`)
	for _, data := range re.FindAllStringSubmatch(args, -1) {
		a[strings.TrimSpace(data[1])] = strings.TrimSpace(data[2])
	}
	return a
}

func PhaseToInt(data string) (int, error) {
	i, err := strconv.Atoi(data)
	if data == "request" {
		i = 2
	} else if data == "response" {
		i = 4
	} else if data == "logging" {
		i = 5
	} else if err != nil || i > 5 || i < 1 {
		return 0, fmt.Errorf("invalid phase %s", data)
	}
	return i, nil
}
