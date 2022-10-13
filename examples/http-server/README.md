## HTTP-Server with Coraza
This example is intended to provide a straightforward way to spin up Coraza and grasp its behaviour.
### Run the example
```
go run . 
```
The server will be reachable at `http://localhost:8090`
### Customize WAF rules
The configuration of the WAF is provided directly inside the code under [main.go](https://github.com/corazawaf/coraza/blob/v3/dev/examples/http-server/main.go#L35). Feel free to play with it.
### Customize server behaviour
Customizing as shown below the [interceptor logic](https://github.com/corazawaf/coraza/blob/v3/dev/http/interceptor.go#L33), it is possible to make the example capable of echoing the body request. It comes in handy for testing rules that match the response body.
```
func (i *rwInterceptor) Write(b []byte) (int, error) {
	buf := new(bytes.Buffer)
	reqReader, err := i.tx.RequestBodyReader()
	if err == nil {
	    _, er := buf.ReadFrom(reqReader)
	 	if er == nil {
	 		b = append(b, buf.Bytes()...)
	 	}
	}
	return i.tx.ResponseBodyWriter().Write(b)
}
```
