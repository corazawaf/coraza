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
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
	urllib "net/url"
	"strconv"
)

type RedisEngine struct {
	rc  *redis.Client
	ctx context.Context
}

func (r *RedisEngine) Init(url string) error {
	r.ctx = context.Background()
	uri, err := urllib.Parse(url)
	if err != nil {
		return err
	}
	password, _ := uri.User.Password()
	path := uri.Path
	if len(path) > 1 {
		path = path[1:] //we remove leading /
	}
	database, err := strconv.Atoi(path)
	if err != nil {
		log.Info("No redis database provided, setting to 0")
	}
	port := uri.Port()
	if port == "" {
		port = "6379"
	}
	host := fmt.Sprintf("%s:%s", uri.Hostname(), port)

	rdb := redis.NewClient(&redis.Options{
		Addr:     host,
		Password: password,
		DB:       database,
	})

	_, err = rdb.Ping(r.ctx).Result()
	if err != nil {
		log.Error("Failed to connecto to redis server.")
		return err
	}
	r.rc = rdb
	return nil
}

func (r *RedisEngine) Get(key string) map[string][]string {
	var res map[string][]string
	val, err := r.rc.Get(r.ctx, key).Result()
	if err != nil {
		return nil
	}
	err = json.Unmarshal([]byte(val), &res)
	if err != nil {
		return nil
	}
	return res
}

func (r *RedisEngine) Set(key string, data map[string][]string) error {
	js, err := json.Marshal(data)
	if err != nil {
		return err
	}
	r.rc.Set(r.ctx, key, js, 0)
	return nil
}
