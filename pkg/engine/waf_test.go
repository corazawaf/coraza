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

func TestRedisConnection(t *testing.T){
	if waf.InitRedis("127.0.0.1", "", "") != nil{
		t.Error("Failed to connect to redis")
	}
}

func TestGeoIP(t *testing.T){
	
}

func TestNewTransaction(t *testing.T){
	
}