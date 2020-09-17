package main

import(
	"testing"
	"net/http"
	"github.com/zalando/skipper/filters"
	"github.com/opentracing/opentracing-go"
)


type testCtx struct{
	//Implements filterContext
	res *http.Response
	req *http.Request
}

func (tc *testCtx) ResponseWriter() http.ResponseWriter{
	return nil
}

func (tc *testCtx) Request() *http.Request{
	if tc.req != nil{
		return tc.req
	}
	req, _ := http.NewRequest("GET", "https://www.github.com/test", nil)
	tc.req = req
	return req
}

func (tc *testCtx) Response() *http.Response {
	if tc.res != nil{
		return tc.res
	}
	client := &http.Client{}
	resp, _ := client.Do(tc.req)
	tc.res = resp
	return resp
}

func (tc *testCtx) OriginalRequest() *http.Request {
	return nil
}

func (tc *testCtx) OriginalResponse() *http.Response {
	return nil
}

func (tc *testCtx) Served() bool {
	return false
}

func (tc *testCtx) MarkServed() {}

func (tc *testCtx) Serve(r *http.Response) {}

func (tc *testCtx) PathParam(string) string {
	return ""
}

func (tc *testCtx) StateBag() map[string]interface{} {
	return nil
}

func (tc *testCtx) BackendUrl() string {
	return ""
}

func (tc *testCtx) OutgoingHost() string {
	return ""
}

func (tc *testCtx) SetOutgoingHost(string) {}

func (tc *testCtx) Metrics() filters.Metrics {
	return nil
}

func (tc *testCtx) Tracer() opentracing.Tracer {
	return nil
}

func (tc *testCtx) ParentSpan() opentracing.Span {
	return nil
}

func (tc *testCtx) Split() (filters.FilterContext, error) {
	return nil, nil
}

func (tc *testCtx) Loopback() {}


func TestSkipper(t *testing.T){
	cs := &CorazaSpec{}
	cfg := make([]interface{}, 1)
	cfg[0] = "../../examples/skipper/default.conf"
	f, err := cs.CreateFilter(cfg)
	if err != nil{
		t.Error(err)
		return
	}
	ctx := &testCtx{}
	f.Request(ctx)
	f.Response(ctx)
}