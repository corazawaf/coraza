package skipper

import(
	"testing"
	"os"
    _"github.com/zalando/skipper"
    _"github.com/zalando/skipper/config"
)

func TestFilterInitialization(t *testing.T){
	config := make([]interface{}, 1)
	pwd, _ := os.Getwd()
	config[0] = pwd + "/../../examples/skipper/default.conf"
	spec := &CorazaSpec{}
	_, err := spec.CreateFilter(config)
	if err != nil{
		t.Error("Error creating skipper filter")
	}
}