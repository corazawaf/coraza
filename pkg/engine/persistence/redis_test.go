package persistence

import(
	"testing"
)

var re *RedisEngine

func TestRedisConnection(t *testing.T){
	re = &RedisEngine{}
	scenarios := []string{"redis://127.0.0.1", "redis://127.0.0.1:6379", "redis://127.0.0.1", "redis://127.0.0.1/0"}
	for _, s := range scenarios{
		err := re.Init(s)
		if err != nil{
			t.Error("Unable to connecto to redis using uri " + s)
		}
	}

	scenarios = []string{"redis://127.0.0.1:12345"}
	for _, s := range scenarios{
		err := re.Init(s)
		if err == nil{
			t.Error("This redis url shouldn't work " + s)
		}
	}	
}

func TestRedisSet(t *testing.T){
	str := map[string][]string{
		"test": []string{"1234"},
	}
	re.Set("test", str)

	if re.Get("test")["test"] == nil || re.Get("test")["test"][0] != "1234"{
		t.Error("Failed to update test key on RedisEngine")
	}
}