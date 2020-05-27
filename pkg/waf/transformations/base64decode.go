package transformations
import(
	"encoding/base64"
)

func Base64decode(data string) string{
	ndata, err := base64.StdEncoding.DecodeString(data)
	if err != nil{
		return data
	}
	return string(ndata)
}