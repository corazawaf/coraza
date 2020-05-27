package operators
import(
	"strings"
	"strconv"
	"fmt"
	"regexp"
	"encoding/hex"
	"github.com/jptosso/coraza-waf/pkg/models"
)

type ValidateByteRange struct{
	ranges []string
}

func (o *ValidateByteRange) Init(data string){
	o.ranges = strings.Split(data, ",")
}

func (o *ValidateByteRange) Evaluate(tx *models.Transaction, data string) bool{
	spl := o.ranges
	rega := []string{}
	for _, br := range spl{
		br = strings.Trim(br, " ")
		b1 := 0
		b2 := 0
		if strings.Contains(br, "-"){
			spl = strings.SplitN(br, "-", 2)
			b1, _ = strconv.Atoi(spl[0])
			b2, _ = strconv.Atoi(spl[1])
		}else{
			b1, _ := strconv.Atoi(br)
			b2 = b1
		}
		b1h := hex.EncodeToString([]byte{byte(b1)})
		b2h := hex.EncodeToString([]byte{byte(b2)})
		rega = append(rega, fmt.Sprintf("[\\x%s-\\x%s]", b1h, b2h))
	}
	rege := strings.Join(rega, "|")
	//fmt.Println(rege)
	re := regexp.MustCompile(rege)
	data = re.ReplaceAllString(data, "")
	//fmt.Printf("%s: %d\n", databack, len(data))
	return len(data) > 0
}