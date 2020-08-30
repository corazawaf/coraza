package transformations
import(
	"github.com/jptosso/coraza-waf/pkg/utils"
)

func RemoveWhitespace(data string) string{
    // loop through all the chars
    newstr := make([]byte, len(data))
    var i, c int
	for (i < len(data)) {
		// remove whitespaces and non breaking spaces (NBSP)
		if (utils.IsSpace(data[i]) || (data[i] == 160)) {
			i++
			continue
		} else {
			newstr[c] += data[i]
			c++
			i++
		}
	}

	//Don't forget to remove the after padding
	return string(newstr[0:c])
}