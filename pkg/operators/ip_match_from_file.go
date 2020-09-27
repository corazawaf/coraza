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

package operators

import (
	log "github.com/sirupsen/logrus"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"strings"
)

type IpMatchFromFile struct {
	ip *IpMatch
}

func (o *IpMatchFromFile) Init(data string) {
	o.ip = &IpMatch{}
	list, err := utils.OpenFile(data)
	if err != nil {
		log.Error("Error opening " + data)
		return
	}
	subnets := strings.ReplaceAll(string(list), "\n", ",")
	o.ip.Init(subnets)
}

func (o *IpMatchFromFile) Evaluate(tx *engine.Transaction, value string) bool {
	return o.ip.Evaluate(tx, value)
}
