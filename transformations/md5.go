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

package transformations

import (
	"crypto/md5"
	"io"
)

func Md5(data string, utils *Tools) string {
	h := md5.New()
	_, err := io.WriteString(h, data)
	if err != nil {
		utils.Logger.Error("error writing md5 string")
	}
	return string(h.Sum(nil))
}
