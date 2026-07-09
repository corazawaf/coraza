# HTTP-Server with Coraza

This example is intended to provide a straightforward way to spin up Coraza and grasp its behaviour.

By default the server is instrumented with the OWASP CRS LTS, embedded via the `coraza-coreruleset` [package](https://github.com/corazawaf/coraza-coreruleset), plus a couple of custom rules.
This is defined in [default.conf](https://github.com/corazawaf/coraza/blob/main/examples/http-server/default.conf).

## Run the example

```bash
# Run the example server with latest local changes
go run .
# Run the example pinning Coraza to the go.mod version
GOWORK=off go run .
```

The server will be reachable at `http://localhost:8090`.

```bash
# True positive request (403 Forbidden) - path traversal blocked by CRS
curl -i 'localhost:8090/?file=../../etc/passwd'
# True positive request (403 Forbidden) - SQL injection blocked by CRS
curl -i "localhost:8090/?q=1' OR '1'='1"
# True positive request (403 Forbidden) - the custom id rule in default.conf
curl -i 'localhost:8090/?id=0'
# True negative request (200 OK)
curl -i 'localhost:8090/'
```

You can swap in your own rules by using the `DIRECTIVES_FILE` environment variable to point at a different directives file (it can still `Include @owasp_crs/*.conf` or similar aliases provided by the embedded CRS filesystem):

```bash
DIRECTIVES_FILE=./my_directives.conf go run .
```

You can also customise response body and response headers by using `RESPONSE_HEADERS` and `RESPONSE_BODY` environment variables respectively:

```bash
RESPONSE_BODY=creditcard DIRECTIVES_FILE=./testdata/response-body.conf go run .
```

And then

```bash
# True positive request (403 Forbidden) due to matching response body
curl -i 'localhost:8090/'
```

## Customize WAF rules

By default the WAF loads [default.conf](https://github.com/corazawaf/coraza/blob/main/examples/http-server/default.conf), which pulls in the OWASP CRS and adds a couple of custom rules. Edit it, or point `DIRECTIVES_FILE` at your own file, to experiment with different rules.

## Customize server behaviour

The following snippet shows an example of code that may be added to the [exampleHandler](https://github.com/corazawaf/coraza/blob/main/examples/http-server/main.go#L17) in order to make the example capable of echoing the body request. It comes in handy for testing rules that match the response body.

```go
func exampleHandler(w http.ResponseWriter, req *http.Request) {
 w.Header().Set("Content-Type", "text/plain")
   var buf bytes.Buffer
 _, err := io.Copy(&buf, req.Body)
   if err != nil {
     log.Fatalf("handler can not read request body: %v", err)
   }
 w.Write(buf.Bytes())
}
```
