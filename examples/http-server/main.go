package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

func hello(w http.ResponseWriter, req *http.Request) {
	// The server generates the response
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Hello world, transaction not disrupted.\n")
}

func main() {
	waf := createWAF()

	http.Handle("/", txhttp.WrapHandler(waf, txhttp.StdLogger, http.HandlerFunc(hello)))

	fmt.Println("Server is running. Listening port: 8090")

	log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().WithErrorLogger(logError).
			WithDirectives(`
				# This is a comment
				SecDebugLogLevel 5
				SecRequestBodyAccess On
				SecResponseBodyAccess On
				SecDebugLog /dev/stdout
				SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
				SecRule REQUEST_BODY "@contains somecontent" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
				SecRule RESPONSE_BODY "@contains someothercontent" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
			`),
	)
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func logError(error ctypes.MatchedRule) {
	msg := error.ErrorLog(0)
	fmt.Printf("[logError][%s] %s", error.Rule.Severity, msg)
}
