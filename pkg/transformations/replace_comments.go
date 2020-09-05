package transformations
import (
	
)

func ReplaceComments(data string) string{
	return doReplaceComments(data)
}

func doReplaceComments(value string) string{
    var i, j int
    incomment := false

    input := []byte(value)
    input_len := len(input)
    for i < input_len {
        if !incomment {
            if ((input[i] == '/') && (i + 1 < input_len) && (input[i + 1] == '*')) {
                incomment = true
                i += 2
            } else {
                input[j] = input[i]
                i++
                j++
            }
        } else {
            if ((input[i] == '*') && (i + 1 < input_len) && (input[i + 1] == '/')) {
                incomment = false
                i += 2
                input[j] = ' '
                j++
            } else {
                i++
            }
        }
    }

    if incomment {
        input[j] = ' '
        j++
    }

    return string(input[0:j]);
}