package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
)

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello world, not disrupted.\n")
}

func main() {
	waf := createWAF()

	http.Handle("/hello", txhttp.WrapHandler(waf, txhttp.StdLogger, http.HandlerFunc(hello)))

	fmt.Println("Server is running. Listening port: 8090")

	log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
		# This is a comment
		SecDebugLogLevel 9
		SecRequestBodyAccess On
		SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
		SecRule REQUEST_BODY "somecontent" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
		SecRule RESPONSE_BODY "somecontent" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	`))
	if err != nil {
		log.Fatal(err)
	}
	return waf
}
