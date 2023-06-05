# HTTP-Server with Coraza

This example is intended to provide a straightforward way to spin up Coraza and grasp its behaviour.

## Run the example

```bash
go run . 
```

The server will be reachable at `http://localhost:8090`.

```bash
# True positive request (403 Forbidden)
curl -i 'localhost:8090/hello?id=0'
# True negative request (200 OK)
curl -i 'localhost:8090/hello'
```

You can customise the rules to be used by using the `DIRECTIVES_FILE` environment variable to load a directives file:

```bash
DIRECTIVES_FILE=my_directives.conf go run . 
```

You can also customise response body and response headers by using `RESPONSE_HEADERS` and `RESPONSE_BODY` environment variables respectively:

```bash
RESPONSE_BODY=creditcard go run . 
```

And then

```bash
# True positive request (403 Forbidden) due to matching response body
curl -i 'localhost:8090/hello'
```

## Customize WAF rules

The configuration of the WAF relies on [default.conf](https://github.com/corazawaf/coraza/blob/main/examples/http-server/default.conf). Feel free to play with it.

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
