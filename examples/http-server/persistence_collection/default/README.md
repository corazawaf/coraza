# HTTP-Server with Coraza

This example is intended to provide example with persistence storage based rulesets.

## Run the example

```bash
go run .
```

The server will be reachable at `http://localhost:8090`.

Example for the rate limit requests from the same X-Real-IP.

```bash
# True negative request (200 OK) // call 3 times
curl --header 'X-Session-ID: unique-session-id' http://localhost:8090/
# True positive request (403 Forbidden) // 4d call
curl --header 'X-Session-ID: unique-session-id' http://localhost:8090/
```
