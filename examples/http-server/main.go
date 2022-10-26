package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	ctypes "github.com/corazawaf/coraza/v3/types"
)

func exampleHandler(w http.ResponseWriter, req *http.Request) {
	resBody := "Hello world, transaction not disrupted."
	w.Header().Set("Content-Type", "text/plain")

	if body := os.Getenv("RESPONSE_BODY"); body != "" {
		resBody = body
	}

	if h := os.Getenv("RESPONSE_HEADERS"); h != "" {
		kv := strings.Split(h, ":")
		w.Header().Set(kv[0], kv[1])
	}

	// The server generates the response
	w.Write([]byte(resBody))
}

func main() {
	waf := createWAF()

	http.Handle("/", txhttp.WrapHandler(waf, txhttp.StdLogger, http.HandlerFunc(exampleHandler)))

	fmt.Println("Server is running. Listening port: 8090")

	log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF {
	directivesFile := "./default.conf"
	if s := os.Getenv("DIRECTIVES_FILE"); s != "" {
		directivesFile = s
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorLogger(logError).
			WithDirectivesFromFile(directivesFile),
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
