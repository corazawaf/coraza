// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Decodes a Base64-encoded string. Unlike base64Decode, this version uses a forgiving implementation, which ignores invalid characters.

package transformations

func base64decodeext(data string) (string, bool, error) {
	res := doBase64decode(data, true)
	return res, true, nil
}
