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
    tx.Capture = true
    str := "https://www.google.com/somesuperdupersearch?id=1"
    if !rx.Evaluate(tx, str){
    	t.Errorf("Failed to match URL")
    }
    if tx.Collections["tx"].Data["0"][0] != str{
    	t.Errorf("Invalid capture 0")	
    }
    if tx.Collections["tx"].Data["1"][0] != "www.google.com"{
    	t.Errorf("Invalid capture 1")	
    }
}

func TestCaptureGroups2(t *testing.T) {
    rx := &Rx{}
    rx.Init(`(?:\b(?:f(?:tp_(?:nb_)?f?(?:ge|pu)t|get(?:s?s|c)|scanf|write|open|read)|gz(?:(?:encod|writ)e|compress|open|read)|s(?:ession_start|candir)|read(?:(?:gz)?file|dir)|move_uploaded_file|(?:proc_|bz)open|call_user_func)|\$_(?:(?:pos|ge)t|session))\b`)
    tx := getTransaction()
    tx.Collections = map[string]*utils.LocalCollection{}
    tx.InitTxCollection()
    tx.Capture = true
    str := "ftp read session_start('test')call_user_func()"
    if !rx.Evaluate(tx, str){
        t.Errorf("Failed to match regex")
    }
    if tx.Collections["tx"].Data["1"][0] != ""{
        t.Errorf("Invalid capture 1")   
    }
}