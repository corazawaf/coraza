package operators
import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/models"
)

func TestCRS920272(t *testing.T) {
    ranges := "32-36,38-126"
	good_strings := [][]int{
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111},
		{38, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 126},
		{32, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 125},
	}

	bad_strings := [][]int{
		{35, 38, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 127, 128},
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, -1},
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 0},
	}

	op := &ValidateByteRange{}
	op.Init(ranges)
	tx := getTransaction()

	for _, gs := range good_strings{
		str := asciiToString(gs)
		if op.Evaluate(tx, str){
			t.Errorf("Invalid byte between ranges (positive): %s", str)
		}
	}

	for _, bs := range bad_strings{
		str := asciiToString(bs)
		if !op.Evaluate(tx, str){
			t.Errorf("Invalid byte between ranges (negative): %s", str)
		}
	}
}


func TestCRS920270(t *testing.T) {
    ranges := "1-255"
	good_strings := [][]int{
		{104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111},
		{38, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 126},
		{32, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 125},
		{1, 104, 101, 108, 111, 32, 119, 97, 122, 122, 117, 112, 32, 98, 114, 111, 255},
	}

	op := &ValidateByteRange{}
	op.Init(ranges)
	tx := getTransaction()

	for _, gs := range good_strings{
		str := asciiToString(gs)
		if !op.Evaluate(tx, str){
			t.Errorf("Invalid null byte: %s", str)
		}
	}
}

func asciiToString(ascii []int) string{
	runes := []rune{}
	for _, a := range ascii{
		runes = append(runes, rune(a))
	}
	return string(runes)
}

func getTransaction() *models.Transaction{
	return &models.Transaction{}
}