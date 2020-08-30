package operators
import(
	"testing"
    "github.com/jptosso/coraza-waf/pkg/engine"
)

func TestCaptureGroups(t *testing.T) {
    rx := &Rx{}
    rx.Init(`^(?i:file|ftps?|https?)://([^/]*).*$`)
    tx := getTransaction()
    tx.Collections = map[string]*engine.LocalCollection{}
    tx.InitTxCollection()
    tx.Capture = true
    str := "https://www.google.com/somesuperdupersearch?id=1"
    if !rx.Evaluate(tx, str){
    	t.Errorf("Failed to match URL")
    }
    if tx.Collections["tx"].Data["0"][0] != str{
    	t.Errorf("Invalid capture 0")	
    }
    if tx.Collections["tx"].Data["1"][0] != "www.google.com"{
    	t.Errorf("Invalid capture 1, got " + tx.Collections["tx"].Data["1"][0])	
    }

    rx.Init(`^(\d+)-(\d+)`)
    if !rx.Evaluate(tx, "4-5"){
        t.Errorf("Invalid @rx for range")   
    }
    if tx.Collections["tx"].Data["1"][0] != "4"{
        t.Errorf("Invalid capture @rx for range")   
    }
    if tx.Collections["tx"].Data["2"][0] != "5"{
        t.Errorf("Invalid capture @rx for range")   
    }    
}

func testRegexMatch(regex string, match string) []string{
    rx := &Rx{}
    rx.Init(regex)
    waf := &engine.Waf{}
    waf.Init()
    tx := waf.NewTransaction()
    tx.Capture = true
    return []string{}
}