// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package persistence

type noopEngine struct{}

func (n noopEngine) Open(uri string, ttl int) error {
	return nil
}

func (noopEngine) Close() error {
	return nil
}

func (noopEngine) Sum(collectionName string, collectionKey string, key string, sum int) error {
	return nil
}

func (noopEngine) Get(collectionName string, collectionKey string, key string) (string, error) {
	return "", nil
}

func (noopEngine) Set(collection string, collectionKey string, key string, value string) error {
	return nil
}

func (noopEngine) Remove(collection string, collectionKey string, key string) error {
	return nil
}

func (noopEngine) All(collection string, collectionKey string) (map[string]string, error) {
	return nil, nil
}

func (noopEngine) SetTTL(collection string, collectionKey string, key string, ttl int) error {
	return nil
}

func init() {
	Register("noop", noopEngine{})
}
