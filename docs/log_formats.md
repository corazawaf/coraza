# Event Log
Located in ``/var/log/coraza-waf/access.log``

## sample Log
```request_address country_iso_core transaction_id session_id "profile_name" "application_id" [date] request_length "method path http_version" response_code response_length waf_action "user_agent"```

```
10.185.248.71 CL ABABABABABABABAB CDCDCDCDCDCDCD "test_profile" "app_id" [09/Jan/2015:19:12:06 +0000] 808840 "GET /inventoryService/inventory/purchaseItem?userId=20253471&itemId=23434300 HTTP/1.1" 500 17 pass "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" [1234 4567] ["sql injection" ""]
```

# Event Log

## Event Trail
Located in ``/var/log/coraza-waf/events.log``

## Audit File
```
{
	"cw_version": "1.0.0",
	"transaction_id": "",
	"app_id": "",
	"profile": "",
	"timestamp": 123,
	"request": {
		"method": "GET",
		"length": 1234

	}, "response": {
		"length": 1234

	}, "events": [
		{
			"rule_id": 1234,
			"phase": 1,
			"msg": "",
			"severity": "",
			"accuracy": 9,
			"maturity": 9,
			"data": "",
			"ver": "",
			"rev": "",
			"action": "block",
			"match": "",
			"tags": ["PCI/6.6.5"]
		}
	]

}
```

## Learning Profile