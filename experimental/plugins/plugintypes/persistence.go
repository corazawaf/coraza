// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

type PersistenceEngine interface {
	Open(uri string, ttl int) error
	Close() error
	Sum(collectionName string, collectionKey string, key string, sum int) error
	Get(collectionName string, collectionKey string, key string) (string, error)

	All(collectionName string, collectionKey string) (map[string]string, error)
	Set(collection string, collectionKey string, key string, value string) error
	Remove(collection string, collectionKey string, key string) error
}
