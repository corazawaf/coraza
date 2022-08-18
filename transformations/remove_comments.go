// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

func removeComments(value string) (string, error) {
	inputLen := len(value)
	// we must add one pad to the right
	input := []byte(value + "\x00")

	var i, j int
	incomment := false

charLoop:
	for i < inputLen {
		if !incomment {
			switch {
			case (input[i] == '/') && (i+1 < inputLen) && (input[i+1] == '*'):
				incomment = true
				i += 2
			case (input[i] == '<') && (i+1 < inputLen) && (input[i+1] == '!') && (i+2 < inputLen) && (input[i+2] == '-') && (i+3 < inputLen) && (input[i+3] == '-') && !incomment:
				incomment = true
				i += 4
			case (input[i] == '-') && (i+1 < inputLen) && (input[i+1] == '-') && !incomment:
				input[i] = ' '
				break charLoop
			case input[i] == '#' && !incomment:
				input[i] = ' '
				break charLoop
			default:
				input[j] = input[i]
				i++
				j++
			}
		} else {
			switch {
			case (input[i] == '*') && (i+1 < inputLen) && (input[i+1] == '/'):
				incomment = false
				i += 2
				input[j] = input[i]
				i++
				j++
			case (input[i] == '-') && (i+1 < inputLen) && (input[i+1] == '-') && (i+2 < inputLen) && (input[i+2] == '>'):
				incomment = false
				i += 3
				input[j] = input[i]
				i++
				j++
			default:
				i++
			}
		}
	}

	if incomment {
		input[j] = ' '
		j++
	}
	return string(input[0:j]), nil
}
