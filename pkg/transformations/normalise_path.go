package transformations
import (
	"path/filepath"
)

func NormalisePath(data string) string{
	return filepath.Clean(data)
}