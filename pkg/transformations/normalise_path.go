package transformations
import (
	"path/filepath"
)

func NormalisePath(data string) string{
	leng := len(data)
	if leng < 1 {
		return data
	}
	clean := filepath.Clean(data)
	if clean == "."{
		return ""
	}
	if leng >= 2 && clean[0] == '.' && clean[1] == '/'{
		clean = clean[2:]
	}
	if data[len(data)-1]  == '/'{
		return clean + "/"
	}else{
		return clean
	}
}

