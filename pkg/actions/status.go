package actions

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

var	HTTP_STATUSES = []int{  100, 101, 102, 103, 200, 
		201, 202, 203, 200, 204, 205, 206, 207, 208, 
		226, 300, 301, 302, 303, 304, 305, 306, 307, 
		302, 308, 301, 400, 401, 402, 403, 404, 405, 
		406, 407, 408, 409, 410, 411, 412, 413, 414, 
		415, 416, 417, 418, 421, 422, 423, 424, 426, 
		428, 429, 431, 451, 500, 501, 502, 503, 504, 
		505, 506, 507, 508, 510, 511, 511 }

type Status struct {
	status int
}

func (a *Status) Init(r *engine.Rule, b1 string) string {
	a.status, _ = strconv.Atoi(b1)
	for _, s := range HTTP_STATUSES{
		if a.status == s{
			return ""
		}
	}
	return "Invalid HTTP status"
}

func (a *Status) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Status = a.status
}

func (a *Status) GetType() int{
	return engine.ACTION_TYPE_DATA
}
