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

func removeCommentsChar(data string) (string, error) {
	value := []byte(data)
	for i := 0; i < len(value); {
		switch {
		case value[i] == '/' && (i+1 < len(value)) && value[i+1] == '*':
			value = erase(value, i, 2)
		case value[i] == '*' && (i+1 < len(value)) && value[i+1] == '/':
			value = erase(value, i, 2)
		case value[i] == '<' &&
			(i+1 < len(value)) &&
			value[i+1] == '!' &&
			(i+2 < len(value)) &&
			value[i+2] == '-' &&
			(i+3 < len(value)) &&
			value[i+3] == '-':
			value = erase(value, i, 4)
		case value[i] == '-' &&
			(i+1 < len(value)) && value[i+1] == '-' &&
			(i+2 < len(value)) && value[i+2] == '>':
			value = erase(value, i, 3)
		case value[i] == '-' && (i+1 < len(value)) && value[i+1] == '-':
			value = erase(value, i, 2)
		case value[i] == '#':
			value = erase(value, i, 1)
		default:
			i++
		}
	}
	return string(value), nil
}

func erase(str []byte, i int, count int) []byte {
	// TODO There are better algorithms to do this but not today
	res := []byte{}
	res = append(res, str[0:i]...)
	res = append(res, str[i+count:]...)
	return res
}
