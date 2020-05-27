package operators

import(
	"testing"
	_"fmt"
	"github.com/jptosso/coraza-waf/test/utils"
	"github.com/jptosso/coraza-waf/pkg/models"
)
/*
func TestDetectSqliUnicodeStringCorrect(t *testing.T) {
    bw := newSqli("")
    tx := newTx()
    for _, data := range utils.SQL_INJECTIONS{
        result := bw.Evaluate(&tx, data)
        if !result {
            t.Errorf("Invalid sql injection test: %q", data)
        }
    }
}

func TestDetectSqliUnicodeStringIncorrect(t *testing.T) {
    data := utils.UnicodeString()
    bw := newSqli(data[3:5])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func TestDetectSqliHugeString(t *testing.T) {
    data := utils.GiantString(1000000)
    bw := newSqli(data[0:115])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func TestDetectSqliEmptyString(t *testing.T) {
    data := ""
    bw := newSqli(data)
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid DetectSqli operator result")
    }
}

func TestDetectSqliBinaryString(t *testing.T) {
    data := utils.BinaryString(1000)
    bw := newSqli(data[0:10])
    tx := newTx()
    result := bw.Evaluate(&tx, data)
    if !result {
    	t.Errorf("Invalid DetectSqli operator result")
    }    
}

func newSqli(data string) models.Operator{
	bw := &DetectSQLi{}
	bw.Init(data)
	return bw
}*/