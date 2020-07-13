package operators

import(
	"github.com/jptosso/coraza-waf/pkg/models"
	"time"
	"os/exec"
	"context"
)

type InspectFile struct{
	path string
}

func (o *InspectFile) Init(data string){
	o.path = data
}

func (o *InspectFile) Evaluate(tx *models.Transaction, value string) bool{
	//TODO parametrize timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    //Add /bin/bash to context?
    cmd := exec.CommandContext(ctx, o.path, value)
    _, err := cmd.CombinedOutput()
    if ctx.Err() == context.DeadlineExceeded || err != nil{
        return false
    }
    return true
}