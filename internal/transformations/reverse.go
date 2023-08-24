// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

func reverse(data string) (string, bool, error) {
	if len(data) <= 1 {
		return data, false, nil
	}
	rns := []rune(data) // convert to rune, not bytes
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		// swap the letters of the string,
		// like first with last and so on.
		rns[i], rns[j] = rns[j], rns[i]
	}
	res := string(rns)
	return res, res != data, nil
}
