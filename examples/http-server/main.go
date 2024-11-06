package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/go-chi/chi/middleware"
)

func exampleHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	resBody := "Hello world, transaction not disrupted."

	if body := os.Getenv("RESPONSE_BODY"); body != "" {
		resBody = body
	}

	if h := os.Getenv("RESPONSE_HEADERS"); h != "" {
		key, val, _ := strings.Cut(h, ":")
		w.Header().Set(key, val)
	}

	// The server generates the response
	w.Write([]byte(resBody))
}

func main() {
	waf := createWAF()

	http.Handle("/", middleware.RequestID( // makes sure the request ID is propagated in the context
		txhttp.WrapHandler(waf, http.HandlerFunc(exampleHandler)),
	))

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
			WithErrorCallback(logError).
			WithDirectivesFromFile(directivesFile),
	)
	if err != nil {
		log.Fatal(err)
	}

	return waf
}

type Contexter interface {
	Context() context.Context
}

func logError(mr types.MatchedRule) {
	msg := mr.ErrorLog()
	if ctxMR, ok := mr.(Contexter); ok {
		if requestID := middleware.GetReqID(ctxMR.Context()); requestID != "" {
			msg = fmt.Sprintf("%s [request_id %q]", msg, requestID)
		}
	}

	fmt.Println(msg)
}
