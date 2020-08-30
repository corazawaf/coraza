package transformations
import (
	"github.com/jptosso/coraza-waf/pkg/utils"
)

func CompressWhitespace(value string) string{
    a := []byte{}
    i := 0
    inWhiteSpace := false
    length := len(value)

    for i < length {
        if (utils.IsSpace(value[i])) {
            if (inWhiteSpace) {
                i++
                continue
            } else {
                inWhiteSpace = true
                a = append(a, ' ')
            }
        } else {
            inWhiteSpace = false
            a = append(a, value[i])
        }
        i++
    }

    return string(a)
}