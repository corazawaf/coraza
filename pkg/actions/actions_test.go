package actions
import(
	"testing"
)
func TestActions(t *testing.T){
	am := ActionsMap()
	if am == nil || len(am) == 0{
		t.Error("Failed to parse actions")
	}
}