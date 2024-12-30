# HTTP-Server with Coraza

This example is intended to provide example with persistence storage based rulesets.

## Run the example

```bash
go run .
```

The server will be reachable at `http://localhost:8090`.

Example for the rate limit requests from the same X-Session-ID:

```bash
curl --header 'X-Session-ID: unique-session-id' http://localhost:8090/
```

- True negative request (200 OK) // 2 calls
- True positive request (403 Forbidden) // 3d call
- Wait for 10 seconds (ttl is set in the `expirevar` directive)
- repeat
