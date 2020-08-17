package engine

import(
	"testing"
)

var waf *Waf

func TestWAFInitialize(t *testing.T){
	waf = &Waf{}
	waf.Init()
	if waf.Rules == nil{
		t.Error("Failed to initialize rule groups")
	}
}

func TestGeoIP(t *testing.T){
	
}

func TestNewTransaction(t *testing.T){
	
}