package operators

import(
	"testing"
	_"fmt"
	"github.com/jptosso/coraza/test/utils"
	"github.com/jptosso/coraza/pkg/models"
)

func TestOpContainsUnicodeStringCorrect(t *testing.T) {
    data := utils.UnicodeString()
    bw := newC(data[0:3])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid BeginsWith transformation result")
    }
}

func TestOpContainsUnicodeStringIncorrect(t *testing.T) {
    data := utils.UnicodeString()
    bw := newC("asdf")
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if result {
    	t.Errorf("Invalid Contains operator result")
    }
}

func TestOpContainsHugeString(t *testing.T) {
    data := utils.GiantString(1000000)
    bw := newC(data[0:115])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid Contains operator result")
    }
}

func TestOpContainsEmptyString(t *testing.T) {
    data := ""
    bw := newC(data)
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid Contains operator result")
    }
}

func TestOpContainsBinaryString(t *testing.T) {
    data := utils.BinaryString(1000)
    bw := newC(data[0:10])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid Contains operator result")
    }    
}

func newC(data string) models.Operator{
	bw := &Contains{}
	bw.Init(data)
	return bw
}