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

package proxy

import (
	"crypto/tls"
)

type TlsConfig struct {
	Config *tls.Config
}

func (tc *TlsConfig) AddCertificate(crt string, key string) error {
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return err
	}
	tc.Config.Certificates = append(tc.Config.Certificates, cert)
	return nil
}

func (tc *TlsConfig) Build() *tls.Config {
	tc.Config.BuildNameToCertificate()
	return tc.Config
}

func NewTlsConfig() *TlsConfig {
	tc := &TlsConfig{
		&tls.Config{},
	}
	tc.Config.Certificates = []tls.Certificate{}
	//TODO add first certificate as placeholder (self-signed)? [0]
	return tc
}
