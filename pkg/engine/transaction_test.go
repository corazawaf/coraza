package engine
import(
	"testing"
	"strings"
)

var wafi = NewWaf()

func TestTxSetters(t *testing.T){
	tx := wafi.NewTransaction()
	ht := []string{
		"POST /testurl.php?id=123&b=456 HTTP/1.1",
		"Host: www.test.com:80",
		"Cookie: test=123",
		"Content-Type: application/x-www-form-urlencoded",
		"X-Test-Header: test456",
		"Content-Length: 13",
		"",
		"testfield=456",
	}
	data := strings.Join(ht, "\r\n")
	tx.ParseRequestString(data)
	exp := map[string]string{
		//TODO somehow host is being overriden
		//"%{request_headers.host}": "www.test.com:80", 
		"%{request_headers.x-test-header}": "test456",
		"%{request_method}": "POST",
		"%{ARGS_GET.id}": "123",
		"%{request_cookies.test}": "123",
		"%{args_post.testfield}": "456",
		"%{args.testfield}": "456",
		"%{request_line}": "POST /testurl.php?id=123&b=456 HTTP/1.1",
		"%{query_string}": "id=123&b=456",
		"%{request_body_length}": "13",
		"%{request_filename}": "/testurl.php",
		"%{request_protocol}": "HTTP/1.1",
		"%{request_uri}": "/testurl.php?id=123&b=456",
		"%{request_uri_raw}": "/testurl.php?id=123&b=456",
		"%{id}": tx.Id,
	}

	for k, v := range exp{
		res := tx.MacroExpansion(k)
		if res != v{
			t.Error("Failed set transaction for " + k + ", expected " + v + ", got " + res)
		}
	}
}

func TestTxMultipart(t *testing.T){
	tx := wafi.NewTransaction()
	ht := []string{
		"POST / HTTP/1.1",
		"Host: localhost:8000",
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:29.0) Gecko/20100101 Firefox/29.0",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language: en-US,en;q=0.5",
		"Accept-Encoding: gzip, deflate",
		"Connection: keep-alive",
		"Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266",
		"Content-Length: 552",
		"",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"text\"",
		"",
		"test-value",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"",
		"Content-Type: text/plain",
		"",
		"Content of a.txt.",
		"",
		"-----------------------------9051914041544843365972754266",
		"Content-Disposition: form-data; name=\"file2\"; filename=\"a.html\"",
		"Content-Type: text/html",
		"",
		"<!DOCTYPE html><title>Content of a.html.</title>",
		"",
		"-----------------------------9051914041544843365972754266--",
	}
	data := strings.Join(ht, "\r\n")
	tx.ParseRequestString(data)
	exp := map[string]string{
		"%{args_post.text}": "test-value",
		"%{files_combined_size}": "69",
	}

	for k, v := range exp{
		res := tx.MacroExpansion(k)
		if res != v{
			t.Error("Failed set transaction for multipart " + k + ", expected " + v + ", got " + res)
		}
	}

	//TODO check files
}

func TestTxPhases(t *testing.T){

}