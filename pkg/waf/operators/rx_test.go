package operators
import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

func TestCaptureGroups(t *testing.T) {
    rx := &Rx{}
    rx.Init(`^(?i:file|ftps?|https?)://([^/]*).*$`)
    tx := getTransaction()
    tx.Collections = map[string]*utils.LocalCollection{}
    tx.InitTxCollection()
    str := "https://www.google.com/somesuperdupersearch?id=1"
    if !rx.Evaluate(tx, str){
    	t.Errorf("Failed to match URL")
    }
    if tx.Collections["tx"].Data["0"][0] != str{
    	t.Errorf("Invalid capture 0")	
    }
    if tx.Collections["tx"].Data["0"][1] != "www.google.com"{
    	t.Errorf("Invalid capture 1")	
    }
}