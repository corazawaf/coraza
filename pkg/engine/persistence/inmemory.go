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

import (
	"errors"
	ttlcache "github.com/ReneKroon/ttlcache/v2"
	"time"
	log "github.com/sirupsen/logrus"
)

type MemoryEngine struct {
	//data map[string]map[string][]string
	data *ttlcache.Cache
}

func (r *MemoryEngine) Init(url string) error {
	r.data = ttlcache.NewCache()
	//TODO r.data.close()
	r.data.SetTTL(time.Duration(1000 * time.Second))
	return nil
}

func (r *MemoryEngine) Get(key string) map[string][]string {
	log.Debug("Getting in memory collection " + key)
	if value, exists := r.data.Get(key); exists == nil {
		return value.(map[string][]string)
	}
	return nil
}

func (r *MemoryEngine) Set(key string, value map[string][]string) error {
	log.Debug("Setting in memory collection " + key)
	r.data.SetWithTTL(key, value, 1000*time.Second)
	return nil
}

func (r *MemoryEngine) Delete(key string) error {
	if result := r.data.Remove(key); result == ttlcache.ErrNotFound {
		return errors.New("Key not found")
	}
	return nil
}
