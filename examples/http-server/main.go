package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello world, not disrupted.\n")
}

func main() {
	waf, err := setupCoraza()
	if err != nil {
		panic(err)
	}
	http.Handle("/hello", corazaRequestHandler(waf, http.HandlerFunc(hello)))

	fmt.Println("Server is running. Listening port: 8090")
	panic(http.ListenAndServe(":8090", nil))
}

func setupCoraza() (coraza.WAF, error) {
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
		return nil, err
	}
	return waf, err
}

func corazaRequestHandler(waf coraza.WAF, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction(context.Background())
		defer func() {
			// We run phase 5 rules and create audit logs (if enabled)
			tx.ProcessLogging()
			// we remove temporary files and free some memory
			if err := tx.Close(); err != nil {
				fmt.Println(err)
			}
		}()
		w = &interceptor{
			origWriter: w,
			tx:         tx,
		}
		/*
			ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
			ProcessRequestHeaders and ProcessRequestBody.
			It fails if any of these functions returns an error and it stops on interruption.
		*/
		if it, err := txhttp.ProcessRequest(tx, r); err != nil {
			showCorazaError(w, 500, err.Error())
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}
		// We continue with the other middlewares by catching the response
		h.ServeHTTP(w, r)
		// we must intercept the response body :(
		if it, err := tx.ProcessResponseBody(); err != nil {
			showCorazaError(w, 500, err.Error())
			return
		} else if it != nil {
			processInterruption(w, it)
			return
		}
		// we release the buffer
		reader, err := tx.ResponseBodyReader()
		if err != nil {
			showCorazaError(w, 500, err.Error())
			return
		}
		if _, err := io.Copy(w, reader); err != nil {
			showCorazaError(w, 500, err.Error())
		}
	}

	return http.HandlerFunc(fn)
}

func processInterruption(w http.ResponseWriter, it *types.Interruption) {
	if it.Status == 0 {
		it.Status = 500
	}
	if it.Action == "deny" {
		showCorazaError(w, it.Status, "Transaction disrupted.")
	}
}

func showCorazaError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	if msg == "" {
		msg = "Unhandled error"
	}
	_, err := fmt.Fprintln(w, msg)
	if err != nil {
		fmt.Println(err)
	}
}
