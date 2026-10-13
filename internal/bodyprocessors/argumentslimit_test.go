// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/internal/persistence"
)

func TestBodyProcessorsArgumentsLimit(t *testing.T) {
	const members = 10

	processors := []struct {
		name string
		mime string
		body string
		// total is the number of shared-budget members the body produces across
		// every collection the processor charges to the argument budget.
		total int
		count func(v plugintypes.TransactionVariables) int
	}{
		{
			name: "json",
			body: func() string {
				b := strings.Builder{}
				b.WriteString("{")
				for i := 0; i < members; i++ {
					if i > 0 {
						b.WriteString(",")
					}
					fmt.Fprintf(&b, `"k%d":"v"`, i)
				}
				b.WriteString("}")
				return b.String()
			}(),
			total: members,
			count: func(v plugintypes.TransactionVariables) int {
				return len(v.ArgsPost().FindAll())
			},
		},
		{
			name: "urlencoded",
			body: func() string {
				pairs := make([]string, 0, members)
				for i := 0; i < members; i++ {
					pairs = append(pairs, fmt.Sprintf("k%d=v", i))
				}
				return strings.Join(pairs, "&")
			}(),
			total: members,
			count: func(v plugintypes.TransactionVariables) int {
				return len(v.ArgsPost().FindAll())
			},
		},
		{
			// REQUEST_XML is budgeted at MaxNodesPerArgument members per unit of
			// the argument limit, so the body carries that many attributes per
			// unit and the member count is converted back into those units.
			name: "xml",
			body: func() string {
				b := strings.Builder{}
				b.WriteString("<root>")
				for i := 0; i < members*bodyprocessors.MaxNodesPerArgument; i++ {
					fmt.Fprintf(&b, `<e a="v%d"/>`, i)
				}
				b.WriteString("</root>")
				return b.String()
			}(),
			total: members,
			count: func(v plugintypes.TransactionVariables) int {
				return len(v.RequestXML().FindAll()) / bodyprocessors.MaxNodesPerArgument
			},
		},
		{
			name: "multipart",
			mime: "multipart/form-data; boundary=X",
			body: func() string {
				b := strings.Builder{}
				for i := 0; i < members; i++ {
					fmt.Fprintf(&b, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\n\r\nv\r\n", i)
				}
				b.WriteString("--X--\r\n")
				return b.String()
			}(),
			// each field part adds one ARGS_POST entry to the shared argument
			// budget; part headers use a separate budget and are not counted here
			total: members,
			count: func(v plugintypes.TransactionVariables) int {
				return len(v.ArgsPost().FindAll())
			},
		},
	}

	for _, p := range processors {
		limits := []struct {
			name    string
			limit   int
			wantErr bool
		}{
			{name: "over_limit", limit: p.total / 2, wantErr: true},
			{name: "at_limit", limit: p.total, wantErr: false},
			{name: "under_limit", limit: p.total * 2, wantErr: false},
			{name: "unlimited", limit: 0, wantErr: false},
		}
		for _, l := range limits {
			t.Run(p.name+"_"+l.name, func(t *testing.T) {
				bp, err := bodyprocessors.GetBodyProcessor(p.name)
				if err != nil {
					t.Fatal(err)
				}
				v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
				err = bp.ProcessRequest(strings.NewReader(p.body), v, plugintypes.BodyProcessorOptions{
					Mime:                      p.mime,
					StoragePath:               t.TempDir(),
					RequestBodyRecursionLimit: 10,
					ArgumentLimit:             l.limit,
				})
				if l.wantErr {
					if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
						t.Fatalf("expected ErrArgumentsLimit, got %v", err)
					}
					if want, have := l.limit, p.count(v); want != have {
						t.Errorf("truncation must fill the collection to the limit and stop, want %d members, have %d", want, have)
					}
				} else {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if want, have := members, p.count(v); want != have {
						t.Errorf("unexpected number of members, want %d, have %d", want, have)
					}
				}
			})
		}
	}
}

// TestXMLArgumentsLimitSharedBudget asserts that attribute values and element
// text nodes are charged against one budget: a document made only of element
// content is bounded, and a document mixing both fills REQUEST_XML to exactly
// the budget across the two kinds of member together. The budget is the
// argument limit scaled by MaxNodesPerArgument.
func TestXMLArgumentsLimitSharedBudget(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("xml")
	if err != nil {
		t.Fatal(err)
	}
	const scale = bodyprocessors.MaxNodesPerArgument
	for _, tc := range []struct {
		name  string
		body  string
		limit int
	}{
		{
			name: "content_only",
			body: func() string {
				b := strings.Builder{}
				b.WriteString("<root>")
				for i := 0; i < 10*scale; i++ {
					fmt.Fprintf(&b, `<e>v%d</e>`, i)
				}
				b.WriteString("</root>")
				return b.String()
			}(),
			limit: 5,
		},
		{
			// Equal numbers of attributes and text nodes, together more than the
			// budget: it must run out across both kinds of member, not per kind.
			name: "attributes_and_content",
			body: func() string {
				b := strings.Builder{}
				b.WriteString("<root>")
				for i := 0; i < 5*scale; i++ {
					fmt.Fprintf(&b, `<e a="a%d">t%d</e>`, i, i)
				}
				b.WriteString("</root>")
				return b.String()
			}(),
			limit: 8,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			err := bp.ProcessRequest(strings.NewReader(tc.body), v, plugintypes.BodyProcessorOptions{
				ArgumentLimit: tc.limit,
			})
			if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
				t.Fatalf("expected ErrArgumentsLimit, got %v", err)
			}
			if want, have := tc.limit*scale, len(v.RequestXML().FindAll()); want != have {
				t.Errorf("REQUEST_XML must hold exactly the budget, want %d members, have %d", want, have)
			}
		})
	}
}

// TestXMLOrdinaryDocumentsAccepted asserts that documents an ordinary client
// sends parse whole at the shipped default limit: a SOAP response of several
// hundred records, a configuration document of several hundred elements and an
// XML-RPC multicall of several hundred parameters all hold more nodes than
// there are arguments in the budget. Reaching ProcessRequest without an error
// is what keeps REQUEST_XML populated and REQBODY_ERROR clear.
func TestXMLOrdinaryDocumentsAccepted(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("xml")
	if err != nil {
		t.Fatal(err)
	}
	soap := strings.Builder{}
	soap.WriteString(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetOrdersResponse xmlns="urn:orders"><Orders>`)
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&soap, `<Order id="%d" currency="EUR"><Number>ORD-%d</Number><Customer>Customer %d</Customer><Total>%d.99</Total></Order>`, i, i, i, i)
	}
	soap.WriteString(`</Orders></GetOrdersResponse></soap:Body></soap:Envelope>`)

	config := strings.Builder{}
	config.WriteString("<configuration>")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&config, `<setting name="option.%d">value %d</setting>`, i, i)
	}
	config.WriteString("</configuration>")

	xmlrpc := strings.Builder{}
	xmlrpc.WriteString(`<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params>`)
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&xmlrpc, `<param><value><string>value %d</string></value></param>`, i)
	}
	xmlrpc.WriteString(`</params></methodCall>`)

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "soap_records", body: soap.String()},
		{name: "config_elements", body: config.String()},
		{name: "xmlrpc_multicall", body: xmlrpc.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			if err := bp.ProcessRequest(strings.NewReader(tc.body), v, plugintypes.BodyProcessorOptions{
				ArgumentLimit: 1000,
			}); err != nil {
				t.Fatalf("rejected a %d byte document holding %d members: %v", len(tc.body), len(v.RequestXML().FindAll()), err)
			}
		})
	}
}

// TestXMLNodeFloodTrips asserts that a node count no document carries still
// exhausts the budget, so REQUEST_XML cannot be grown without bound.
func TestXMLNodeFloodTrips(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("xml")
	if err != nil {
		t.Fatal(err)
	}
	const limit = 1000
	body := strings.Builder{}
	body.WriteString("<root>")
	for i := 0; i < limit*bodyprocessors.MaxNodesPerArgument*2; i++ {
		fmt.Fprintf(&body, `<e a="v%d">t%d</e>`, i, i)
	}
	body.WriteString("</root>")

	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		ArgumentLimit: limit,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if want, have := limit*bodyprocessors.MaxNodesPerArgument, len(v.RequestXML().FindAll()); want != have {
		t.Errorf("REQUEST_XML must hold exactly the budget, want %d members, have %d", want, have)
	}
}

// TestJSONLargeBodiesAccepted asserts the decoded-bytes budget does not reject
// legitimate bodies: it scales with the input, so large flat bodies and
// realistically nested ones parse without error.
func TestJSONLargeBodiesAccepted(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}

	// Large flat bodies at two sizes, each staying under ArgumentLimit members.
	for _, members := range []int{200, 900} {
		t.Run(fmt.Sprintf("flat_%d_members", members), func(t *testing.T) {
			value := strings.Repeat("x", 6000)
			body := strings.Builder{}
			body.WriteString("{")
			for i := 0; i < members; i++ {
				if i > 0 {
					body.WriteString(",")
				}
				fmt.Fprintf(&body, `"field_name_%d":"%s"`, i, value)
			}
			body.WriteString("}")

			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			if err := bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
				RequestBodyRecursionLimit: 1024,
				ArgumentLimit:             1000,
			}); err != nil {
				t.Fatalf("rejected a %d byte flat body: %v", body.Len(), err)
			}
			if want, have := members, len(v.ArgsPost().FindAll()); want != have {
				t.Errorf("unexpected number of members, want %d, have %d", want, have)
			}
		})
	}

	// A nested body with descriptive key names: an array of records each
	// holding a nested object. Its flattened paths are far longer than a flat
	// body's, which is what the slack in the budget covers.
	t.Run("nested_records", func(t *testing.T) {
		payload := strings.Repeat("y", 10000)
		body := strings.Builder{}
		body.WriteString(`{"records":[`)
		for i := 0; i < 300; i++ {
			if i > 0 {
				body.WriteString(",")
			}
			fmt.Fprintf(&body, `{"id":%d,"payload":"%s","metadata":{"tag":"tag%d"}}`, i, payload, i)
		}
		body.WriteString("]}")

		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		if err := bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
			RequestBodyRecursionLimit: 1024,
			ArgumentLimit:             1000,
		}); err != nil {
			t.Fatalf("rejected a %d byte nested body: %v", body.Len(), err)
		}
		// 300 records x (id, payload, metadata.tag), plus the length of the
		// records array.
		if want, have := 901, len(v.ArgsPost().FindAll()); want != have {
			t.Errorf("unexpected number of members, want %d, have %d", want, have)
		}
	})

	// Deeply nested with long-ish key names, still under the member cap.
	t.Run("deep_config", func(t *testing.T) {
		var build func(depth, fanout int) string
		build = func(depth, fanout int) string {
			if depth == 0 {
				return `"value"`
			}
			s := strings.Builder{}
			s.WriteString("{")
			for i := 0; i < fanout; i++ {
				if i > 0 {
					s.WriteString(",")
				}
				fmt.Fprintf(&s, `"configuration_section_%d":%s`, i, build(depth-1, fanout))
			}
			s.WriteString("}")
			return s.String()
		}
		body := build(9, 2)

		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
			RequestBodyRecursionLimit: 1024,
			ArgumentLimit:             1000,
		}); err != nil {
			t.Fatalf("rejected a %d byte deeply nested body: %v", len(body), err)
		}
		// A binary tree of depth 9 carries one leaf per path, and the body holds
		// no arrays, so no length entry is recorded.
		if want, have := 512, len(v.ArgsPost().FindAll()); want != have {
			t.Errorf("unexpected number of members, want %d, have %d", want, have)
		}
	})
}

func TestJSONResponseArgumentsLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Builder{}
	body.WriteString("{")
	for i := 0; i < 10; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, `"k%d":"v"`, i)
	}
	body.WriteString("}")

	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessResponse(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: 10,
		ArgumentLimit:              5,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if want, have := 5, len(v.ResponseArgs().FindAll()); want != have {
		t.Errorf("the collection must fill to the limit, want %d members, have %d", want, have)
	}

	v = corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	if err := bp.ProcessResponse(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: 10,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want, have := 10, len(v.ResponseArgs().FindAll()); want != have {
		t.Errorf("unexpected number of members, want %d, have %d", want, have)
	}
}

// TestMultipartFilePartsArgumentsLimit asserts that a file part costs one
// member of the argument budget, so a form may carry exactly ArgumentLimit file
// parts and a bulk upload of several hundred passes at the shipped default.
// FILES, FILES_NAMES, FILES_SIZES and FILES_TMP_NAMES are four views of the
// same part and are charged once between them, which also keeps the outcome
// independent of environment.HasAccessToFS. Part headers use their own budget,
// so every part the parse reaches records its Content-Disposition.
func TestMultipartFilePartsArgumentsLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		limit   int
		files   int
		wantErr bool
	}{
		{name: "bulk_upload_at_default_limit", limit: 1000, files: 400},
		{name: "at_limit", limit: 12, files: 12},
		{name: "over_limit", limit: 12, files: 13, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Builder{}
			for i := 0; i < tc.files; i++ {
				fmt.Fprintf(&body, "--X\r\nContent-Disposition: form-data; name=\"f%d\"; filename=\"file%d.txt\"\r\n\r\ndata\r\n", i, i)
			}
			body.WriteString("--X--\r\n")

			dir := t.TempDir()
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			err := bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
				Mime:          "multipart/form-data; boundary=X",
				StoragePath:   dir,
				ArgumentLimit: tc.limit,
			})
			wantFiles := tc.files
			wantHeaders := tc.files
			if tc.wantErr {
				if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
					t.Fatalf("expected ErrArgumentsLimit, got %v", err)
				}
				wantFiles = tc.limit
				// The part that exhausts the budget is stopped after its headers
				// were recorded.
				wantHeaders = tc.limit + 1
			} else if err != nil {
				t.Fatalf("rejected %d file parts under a limit of %d: %v", tc.files, tc.limit, err)
			}
			for _, col := range []struct {
				name    string
				members int
			}{
				{"FILES", len(v.Files().FindAll())},
				{"FILES_NAMES", len(v.FilesNames().FindAll())},
				{"FILES_SIZES", len(v.FilesSizes().FindAll())},
			} {
				if want, have := wantFiles, col.members; want != have {
					t.Errorf("unexpected %s members, want %d, have %d", col.name, want, have)
				}
			}
			if environment.HasAccessToFS {
				if want, have := wantFiles, len(v.FilesTmpNames().FindAll()); want != have {
					t.Errorf("unexpected FILES_TMP_NAMES members, want %d, have %d", want, have)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if want, have := wantFiles, len(entries); want != have {
					t.Errorf("unexpected number of temp files, want %d, have %d", want, have)
				}
			}
			if want, have := wantHeaders, len(v.MultipartPartHeaders().FindAll()); want != have {
				t.Errorf("unexpected MULTIPART_PART_HEADERS members, want %d, have %d", want, have)
			}
		})
	}
}

// TestMultipartMixedPartsShareOneBudget asserts that field and file parts draw
// on the same budget at one member each, so a form of files and fields is
// admitted up to the total number of parts.
func TestMultipartMixedPartsShareOneBudget(t *testing.T) {
	const limit = 20
	body := strings.Builder{}
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&body, "--X\r\nContent-Disposition: form-data; name=\"f%d\"; filename=\"file%d.txt\"\r\n\r\ndata\r\n", i, i)
		fmt.Fprintf(&body, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\n\r\nv\r\n", i)
	}
	body.WriteString("--X--\r\n")

	bp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	if err := bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		Mime:          "multipart/form-data; boundary=X",
		StoragePath:   t.TempDir(),
		ArgumentLimit: limit,
	}); err != nil {
		t.Fatalf("rejected %d parts under a limit of %d: %v", limit, limit, err)
	}
	if want, have := 10, len(v.Files().FindAll()); want != have {
		t.Errorf("unexpected FILES members, want %d, have %d", want, have)
	}
	if want, have := 10, len(v.ArgsPost().FindAll()); want != have {
		t.Errorf("unexpected ARGS_POST members, want %d, have %d", want, have)
	}
}

// TestMultipartHeaderFlood asserts that a part-header flood on the first part
// does not empty the argument collections, and that when the flood does exhaust
// the header budget the parse reports ErrArgumentsLimit: MULTIPART_PART_HEADERS
// then holds nothing for the later parts, so a ruleset has to be able to see
// that the collection is incomplete.
func TestMultipartHeaderFlood(t *testing.T) {
	const limit = 1000
	const headerLimit = limit * bodyprocessors.MaxHeadersPerPart

	for _, tc := range []struct {
		name             string
		junk             int
		wantErr          bool
		wantLaterHeaders int
	}{
		{name: "under_budget", junk: 10, wantErr: false, wantLaterHeaders: 1},
		{name: "over_budget", junk: headerLimit + 200, wantErr: true, wantLaterHeaders: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Builder{}
			body.WriteString("--X\r\nContent-Disposition: form-data; name=\"junk\"\r\n")
			for i := 0; i < tc.junk; i++ {
				fmt.Fprintf(&body, "x%d: b\r\n", i)
			}
			body.WriteString("\r\npad\r\n")
			body.WriteString("--X\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\nvalue\r\n")
			body.WriteString("--X--\r\n")

			bp, err := bodyprocessors.GetBodyProcessor("multipart")
			if err != nil {
				t.Fatal(err)
			}
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			err = bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
				Mime:          "multipart/form-data; boundary=X",
				StoragePath:   t.TempDir(),
				ArgumentLimit: limit,
			})
			if tc.wantErr {
				if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
					t.Fatalf("header truncation not reported, want ErrArgumentsLimit, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// The argument collections fill regardless of the header flood.
			if want, have := 1, len(v.ArgsPost().Get("q")); want != have {
				t.Errorf("malicious field dropped by header flood: want %d value, have %d", want, have)
			}
			if have := len(v.MultipartPartHeaders().FindAll()); have > headerLimit {
				t.Errorf("MULTIPART_PART_HEADERS exceeds its budget: have %d", have)
			}
			if want, have := tc.wantLaterHeaders, len(v.MultipartPartHeaders().Get("q")); want != have {
				t.Errorf("unexpected headers recorded for the later part, want %d, have %d", want, have)
			}
		})
	}
}

// TestMultipartHeaderTruncationDeterministic asserts that when the part-header
// budget runs out mid-part, the headers kept are the same on every run: they
// are recorded in sorted key order rather than header map order.
func TestMultipartHeaderTruncationDeterministic(t *testing.T) {
	const limit = 4
	const headerLimit = limit * bodyprocessors.MaxHeadersPerPart
	// One part offering more headers than the budget admits, so the recorded
	// ones are a prefix of the sorted keys.
	b := strings.Builder{}
	b.WriteString("--X\r\nContent-Disposition: form-data; name=\"f\"\r\n")
	want := []string{`Content-Disposition: form-data; name="f"`}
	for i := 0; i < headerLimit+8; i++ {
		fmt.Fprintf(&b, "X-A%02d: %d\r\n", i, i)
		if len(want) < headerLimit {
			want = append(want, fmt.Sprintf("X-A%02d: %d", i, i))
		}
	}
	b.WriteString("\r\nv\r\n--X--\r\n")
	body := b.String()

	bp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
			Mime:          "multipart/form-data; boundary=X",
			StoragePath:   t.TempDir(),
			ArgumentLimit: limit,
		})
		if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
			t.Fatalf("run %d: expected ErrArgumentsLimit, got %v", i, err)
		}
		if have := v.MultipartPartHeaders().Get("f"); !reflect.DeepEqual(want, have) {
			t.Fatalf("run %d: truncation is not a stable prefix, want %q, have %q", i, want, have)
		}
	}
}

type forkErrReader struct{}

func (forkErrReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestMultipartTempFileAlwaysRegistered asserts that a temp file created for a
// file part is recorded in FILES_TMP_NAMES even when the part fails to be
// copied, because transaction cleanup only removes the files listed there.
func TestMultipartTempFileAlwaysRegistered(t *testing.T) {
	if !environment.HasAccessToFS {
		t.Skip("no filesystem access")
	}
	head := "--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\n"
	body := io.MultiReader(strings.NewReader(head+strings.Repeat("A", 8192)), forkErrReader{})

	bp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	if err := bp.ProcessRequest(body, v, plugintypes.BodyProcessorOptions{
		Mime:        "multipart/form-data; boundary=X",
		StoragePath: dir,
	}); err == nil {
		t.Fatal("expected the copy to fail")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected a temp file to have been created")
	}
	if want, have := len(entries), len(v.FilesTmpNames().FindAll()); want != have {
		t.Errorf("%d temp files on disk but %d in FILES_TMP_NAMES: unregistered files are never cleaned up", want, have)
	}
}

// TestJSONTruncatedArrayLength asserts that stopping inside an array does not
// record the array length under a path the document does not have, and that the
// flatten byte budget names itself instead of pointing at SecArgumentsLimit.
func TestJSONTruncatedArrayLength(t *testing.T) {
	body := strings.Builder{}
	body.WriteString(`[{"`)
	body.WriteString(strings.Repeat("K", 400))
	body.WriteString(`":{`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, `"%d":1`, i)
	}
	body.WriteString("}}]")

	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 1024,
	})
	if !errors.Is(err, bodyprocessors.ErrJSONLimit) || errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected the flatten byte budget error, got %v", err)
	}
	if !strings.Contains(err.Error(), "byte budget") {
		t.Errorf("the flatten byte budget is not reported under its own name: %q", err)
	}
	// The enclosing array stopped on the error its element raised, so it has no
	// length entry either.
	if have := v.ArgsPost().Get("json"); len(have) != 0 {
		t.Errorf("the enclosing array reports a length after stopping early: json = %q", have)
	}
}

// TestJSONTruncatedArrayLengthNotRecorded asserts that an array whose iteration
// stopped early records no length entry: the elements past the stop were never
// counted, so any number written there would understate the array and let a
// rule counting its size be talked down by a body shaped to trip the limit.
func TestJSONTruncatedArrayLengthNotRecorded(t *testing.T) {
	body := strings.Builder{}
	body.WriteString(`{"a":[`)
	for i := 0; i < 10; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, "%d", i)
	}
	body.WriteString("]}")

	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 10,
		ArgumentLimit:             5,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if have := v.ArgsPost().Get("json.a"); len(have) != 0 {
		t.Errorf("a truncated array reports a length, json.a = %q, the array holds 10 elements", have)
	}
}

// TestJSONArgumentCountLimitError asserts that the argument count limit still
// reports the plain sentinel, so raising SecArgumentsLimit is an actionable
// answer to that message.
func TestJSONArgumentCountLimitError(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(`{"a":1,"b":2,"c":3}`), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 10,
		ArgumentLimit:             2,
	})
	// Compared by identity: this path must report the count limit unwrapped.
	if err != bodyprocessors.ErrArgumentsLimit {
		t.Fatalf("expected the bare sentinel, got %v", err)
	}
}

// TestMultipartHeaderBudgetExactLimit offers one header more than the budget
// admits: exactly the budget must be recorded and the truncation reported.
func TestMultipartHeaderBudgetExactLimit(t *testing.T) {
	const limit = 5
	const headerLimit = limit * bodyprocessors.MaxHeadersPerPart
	body := strings.Builder{}
	body.WriteString("--X\r\nContent-Disposition: form-data; name=\"f\"\r\n")
	// Content-Disposition already counts as one header; add headerLimit more so
	// the budget is exceeded and must stop at exactly headerLimit recorded
	// headers.
	for i := 0; i < headerLimit; i++ {
		fmt.Fprintf(&body, "x%d: b\r\n", i)
	}
	body.WriteString("\r\nv\r\n")
	body.WriteString("--X--\r\n")

	bp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		Mime:          "multipart/form-data; boundary=X",
		StoragePath:   t.TempDir(),
		ArgumentLimit: limit,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if want, have := headerLimit, len(v.MultipartPartHeaders().FindAll()); want != have {
		t.Errorf("part-header budget not filled to exactly the limit: want %d, have %d", want, have)
	}
}

// TestURLEncodedTruncationDeterministic asserts that truncation keeps the
// first ArgumentLimit values in document order on every run.
func TestURLEncodedTruncationDeterministic(t *testing.T) {
	const body = "a=1&a=2&a=3&a=4&b=1&c=1&d=1"
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
			ArgumentLimit: 5,
		})
		if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
			t.Fatalf("run %d: expected ErrArgumentsLimit, got %v", i, err)
		}
		if want, have := 5, len(v.ArgsPost().FindAll()); want != have {
			t.Fatalf("run %d: unexpected number of members, want %d, have %d", i, want, have)
		}
		for key, want := range map[string]int{"a": 4, "b": 1, "c": 0, "d": 0} {
			if have := len(v.ArgsPost().Get(key)); want != have {
				t.Fatalf("run %d: unexpected number of values for %q, want %d, have %d", i, key, want, have)
			}
		}
	}
}

// TestURLEncodedRepeatedKeyFillsToLimit asserts that a single key with more
// values than the limit still fills ARGS_POST up to the limit.
func TestURLEncodedRepeatedKeyFillsToLimit(t *testing.T) {
	pairs := make([]string, 0, 1002)
	for i := 0; i < 1002; i++ {
		pairs = append(pairs, fmt.Sprintf("evil=%d", i))
	}
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(strings.Join(pairs, "&")), v, plugintypes.BodyProcessorOptions{
		ArgumentLimit: 1000,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	values := v.ArgsPost().Get("evil")
	if want, have := 1000, len(values); want != have {
		t.Fatalf("unexpected number of values, want %d, have %d", want, have)
	}
	if values[0] != "0" || values[999] != "999" {
		t.Errorf("values are not in document order: first %q, last %q", values[0], values[999])
	}
}

// TestJSONRawBodyStoredOnArgumentsLimit asserts that TX:json_request_body and
// TX:json_response_body keep the raw body when the argument limit trips, so
// @validateSchema still has data to validate.
func TestJSONRawBodyStoredOnArgumentsLimit(t *testing.T) {
	body := strings.Builder{}
	body.WriteString("{")
	for i := 0; i < 10; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, `"k%d":"v"`, i)
	}
	body.WriteString("}")

	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}

	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 10,
		ArgumentLimit:             5,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if have := v.TX().Get("json_request_body"); len(have) != 1 || have[0] != body.String() {
		t.Errorf("TX:json_request_body does not hold the raw body: %q", have)
	}

	v = corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessResponse(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: 10,
		ArgumentLimit:              5,
	})
	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if have := v.TX().Get("json_response_body"); len(have) != 1 || have[0] != body.String() {
		t.Errorf("TX:json_response_body does not hold the raw body: %q", have)
	}
}

// TestJSONResponseDepthLimit asserts that the response path applies the
// configured recursion limit.
func TestJSONResponseDepthLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	// 50 levels stay under upstream's flatten byte budget (see
	// TestJSONArgumentFreeBodiesAreNotDenied), so only the depth limit decides.
	body := strings.Repeat("[", 50) + strings.Repeat("]", 50)

	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	err = bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: 25,
	})
	if err == nil || errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected recursion error, got %v", err)
	}
	// The raw body must still be stored for @validateSchema even though the
	// depth limit stopped the parse before any argument was flattened.
	if have := v.TX().Get("json_response_body"); len(have) != 1 || have[0] != body {
		t.Errorf("TX:json_response_body not stored on the depth-error path: %q", have)
	}

	v = corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: 100,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestArgumentsLimitStopsReading asserts that once the limit trips, the XML
// and multipart processors stop consuming the body instead of parsing it to
// the end and trimming afterwards.
func TestArgumentsLimitStopsReading(t *testing.T) {
	xmlBody := strings.Builder{}
	xmlBody.WriteString("<root>")
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&xmlBody, `<e a="v%d"/>`, i)
	}
	xmlBody.WriteString("</root>")

	multipartBody := strings.Builder{}
	for i := 0; i < 50000; i++ {
		fmt.Fprintf(&multipartBody, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\n\r\nv\r\n", i)
	}
	multipartBody.WriteString("--X--\r\n")

	for _, tc := range []struct {
		name string
		mime string
		body string
	}{
		{name: "xml", body: xmlBody.String()},
		{name: "multipart", mime: "multipart/form-data; boundary=X", body: multipartBody.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bp, err := bodyprocessors.GetBodyProcessor(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			cr := &countingReader{r: strings.NewReader(tc.body)}
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			err = bp.ProcessRequest(cr, v, plugintypes.BodyProcessorOptions{
				Mime:          tc.mime,
				StoragePath:   t.TempDir(),
				ArgumentLimit: 10,
			})
			if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
				t.Fatalf("expected ErrArgumentsLimit, got %v", err)
			}
			if cr.n >= 64<<10 {
				t.Errorf("processor read %d bytes of a %d byte body after the limit tripped", cr.n, len(tc.body))
			}
		})
	}
}

// TestURLEncodedArgumentsLimitAllocs asserts that arguments past the limit are
// never decoded into an intermediate map: the allocation volume must stay
// close to the raw body copy rather than growing with the argument count.
func TestURLEncodedArgumentsLimitAllocs(t *testing.T) {
	pairs := make([]string, 0, 100000)
	for i := 0; i < 100000; i++ {
		pairs = append(pairs, fmt.Sprintf("key%06d=value", i))
	}
	body := strings.Join(pairs, "&")

	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err = bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ArgumentLimit: 10,
	})
	runtime.ReadMemStats(&after)

	if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
		t.Fatalf("expected ErrArgumentsLimit, got %v", err)
	}
	if want, have := 10, len(v.ArgsPost().FindAll()); want != have {
		t.Fatalf("unexpected number of members, want %d, have %d", want, have)
	}
	// The raw body is copied once for REQUEST_BODY (~len(body) bytes); parsing
	// all 100k arguments into a map would add several times that.
	allocated := after.TotalAlloc - before.TotalAlloc
	if maxAllocated := uint64(len(body)) + 1<<20; allocated > maxAllocated {
		t.Errorf("allocated %d bytes, expected at most %d", allocated, maxAllocated)
	}
}

// TestMultipartTypedPartsWithinArgumentLimit asserts that a form of
// ArgumentLimit ordinary parts is accepted whole. Two headers per part is the
// worst case an ordinary client produces, a Content-Disposition plus the
// Content-Type clients attach to typed parts, and the part-header budget must
// stay clear of a form built that way.
func TestMultipartTypedPartsWithinArgumentLimit(t *testing.T) {
	const limit = 1000
	body := strings.Builder{}
	for i := 0; i < limit; i++ {
		fmt.Fprintf(&body, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\nContent-Type: text/plain\r\n\r\nv\r\n", i)
	}
	body.WriteString("--X--\r\n")

	bp, err := bodyprocessors.GetBodyProcessor("multipart")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	if err := bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		Mime:          "multipart/form-data; boundary=X",
		StoragePath:   t.TempDir(),
		ArgumentLimit: limit,
	}); err != nil {
		t.Fatalf("rejected %d typed parts under a limit of %d: %v", limit, limit, err)
	}
	if want, have := limit, len(v.ArgsPost().FindAll()); want != have {
		t.Errorf("unexpected ARGS_POST members, want %d, have %d", want, have)
	}
	if want, have := 2*limit, len(v.MultipartPartHeaders().FindAll()); want != have {
		t.Errorf("unexpected MULTIPART_PART_HEADERS members, want %d, have %d", want, have)
	}
}

// TestJSONRawBodyStoredOnParseFailure asserts that the raw request body reaches
// TX:json_request_body even when parsing fails outright. Operators like
// @validateSchema read that variable, and a body the flattener rejects is
// exactly the one a schema check most needs to see.
func TestJSONRawBodyStoredOnParseFailure(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body string
		opts plugintypes.BodyProcessorOptions
	}{
		{name: "invalid json", body: "{invalid"},
		{
			name: "over the recursion limit",
			body: strings.Repeat("[", 200) + strings.Repeat("]", 200),
			opts: plugintypes.BodyProcessorOptions{RequestBodyRecursionLimit: 100},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			if err := bp.ProcessRequest(strings.NewReader(tc.body), v, tc.opts); err == nil {
				t.Fatal("expected the parse to fail")
			}
			have := v.TX().Get("json_request_body")
			if len(have) != 1 || have[0] != tc.body {
				t.Errorf("the raw body must survive a failed parse, want %q, have %q", tc.body, have)
			}
		})
	}
}

// TestScaledBudgetsDoNotOverflow asserts that a large SecArgumentsLimit leaves
// benign bodies accepted. The multipart and XML budgets, and the bound on JSON
// members, scale the limit by a constant factor; on a 32-bit target that
// product wraps negative unless it saturates, and a negative budget reads as
// "nothing fits" or as "unlimited" depending on the comparison, so the same
// request would be answered differently by a 32-bit and a 64-bit build.
func TestScaledBudgetsDoNotOverflow(t *testing.T) {
	for _, tc := range []struct {
		processor string
		mime      string
		body      string
		collect   func(plugintypes.TransactionVariables) int
	}{
		{
			processor: "multipart",
			mime:      "multipart/form-data; boundary=X",
			body:      "--X\r\nContent-Disposition: form-data; name=\"k\"\r\nContent-Type: text/plain\r\n\r\nv\r\n--X--\r\n",
			collect:   func(v plugintypes.TransactionVariables) int { return len(v.ArgsPost().FindAll()) },
		},
		{
			processor: "xml",
			body:      `<r a="1"><f>v</f></r>`,
			collect:   func(v plugintypes.TransactionVariables) int { return len(v.RequestXML().FindAll()) },
		},
		{
			processor: "json",
			body:      `{"a":[1,2,3],"b":"v"}`,
			collect:   func(v plugintypes.TransactionVariables) int { return len(v.ArgsPost().FindAll()) },
		},
	} {
		t.Run(tc.processor, func(t *testing.T) {
			bp, err := bodyprocessors.GetBodyProcessor(tc.processor)
			if err != nil {
				t.Fatal(err)
			}
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			if err := bp.ProcessRequest(strings.NewReader(tc.body), v, plugintypes.BodyProcessorOptions{
				Mime:                      tc.mime,
				RequestBodyRecursionLimit: 1024,
				ArgumentLimit:             math.MaxInt,
			}); err != nil {
				t.Fatalf("a benign body was rejected under a large argument limit: %v", err)
			}
			if have := tc.collect(v); have == 0 {
				t.Error("a benign body stored no members under a large argument limit")
			}
		})
	}
}

// TestJSONSiblingArrayLengthsNotCountedAsArguments asserts the array-length
// exemption across several arrays rather than one. A body whose scalars are
// spread over many sibling arrays carries one length entry per array, and if
// any of them were charged as an argument the body would be denied while
// holding exactly ArgumentLimit values.
func TestJSONSiblingArrayLengthsNotCountedAsArguments(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	const (
		arrays          = 50
		scalarsPerArray = 2
		limit           = arrays * scalarsPerArray
	)
	b := strings.Builder{}
	b.WriteString("{")
	for i := 0; i < arrays; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%d":[1,2]`, i)
	}
	b.WriteString("}")

	v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
	if err := bp.ProcessRequest(strings.NewReader(b.String()), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 1024,
		ArgumentLimit:             limit,
	}); err != nil {
		t.Fatalf("a body of exactly %d values was rejected: %v", limit, err)
	}
	// The scalars plus one length entry per array.
	if want, have := limit+arrays, len(v.ArgsPost().FindAll()); want != have {
		t.Errorf("unexpected number of members, want %d, have %d", want, have)
	}
}

// TestScaledBudgetsHaveLiteralAnchors pins the two scaling constants against
// concrete documents and literal member counts. Assertions written in terms of
// MaxNodesPerArgument or MaxHeadersPerPart move with the constant and so cannot
// detect a change to it; these cases fail if either is narrowed enough to
// reject ordinary traffic or widened enough to stop bounding a flood.
func TestScaledBudgetsHaveLiteralAnchors(t *testing.T) {
	const limit = 1000

	t.Run("xml_ordinary_document_accepted", func(t *testing.T) {
		bp, _ := bodyprocessors.GetBodyProcessor("xml")
		b := strings.Builder{}
		b.WriteString(`<soap:Envelope xmlns:soap="urn:e"><soap:Body><Orders>`)
		for i := 0; i < 1200; i++ {
			fmt.Fprintf(&b, `<Order id="%d" currency="EUR"><Number>ORD-%d</Number><Customer>C%d</Customer><Total>%d.99</Total></Order>`, i, i, i, i)
		}
		b.WriteString(`</Orders></soap:Body></soap:Envelope>`)
		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		if err := bp.ProcessRequest(strings.NewReader(b.String()), v, plugintypes.BodyProcessorOptions{ArgumentLimit: limit}); err != nil {
			t.Fatalf("an ordinary SOAP document of 1200 records was rejected: %v", err)
		}
		// 1200 records x (2 attributes + 3 text nodes), plus the envelope's
		// namespace attribute.
		if want, have := 6001, len(v.RequestXML().FindAll()); want != have {
			t.Errorf("unexpected REQUEST_XML members, want %d, have %d", want, have)
		}
	})

	t.Run("xml_node_flood_trips", func(t *testing.T) {
		bp, _ := bodyprocessors.GetBodyProcessor("xml")
		b := strings.Builder{}
		b.WriteString("<root>")
		for i := 0; i < 20000; i++ {
			fmt.Fprintf(&b, `<e a="v%d"/>`, i)
		}
		b.WriteString("</root>")
		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		err := bp.ProcessRequest(strings.NewReader(b.String()), v, plugintypes.BodyProcessorOptions{ArgumentLimit: limit})
		if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
			t.Fatalf("a flood of 20000 nodes did not trip the budget: %v", err)
		}
	})

	t.Run("multipart_ordinary_form_accepted", func(t *testing.T) {
		bp, _ := bodyprocessors.GetBodyProcessor("multipart")
		b := strings.Builder{}
		for i := 0; i < 900; i++ {
			fmt.Fprintf(&b, "--X\r\nContent-Disposition: form-data; name=\"k%d\"\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: binary\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\n\r\nv\r\n", i)
		}
		b.WriteString("--X--\r\n")
		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		if err := bp.ProcessRequest(strings.NewReader(b.String()), v, plugintypes.BodyProcessorOptions{
			Mime: "multipart/form-data; boundary=X", ArgumentLimit: limit, StoragePath: t.TempDir(),
		}); err != nil {
			t.Fatalf("an ordinary form of 900 parts carrying 6 headers each was rejected: %v", err)
		}
		// 900 parts x 6 headers.
		if want, have := 5400, len(v.MultipartPartHeaders().FindAll()); want != have {
			t.Errorf("unexpected MULTIPART_PART_HEADERS members, want %d, have %d", want, have)
		}
	})

	t.Run("multipart_header_flood_trips", func(t *testing.T) {
		bp, _ := bodyprocessors.GetBodyProcessor("multipart")
		b := strings.Builder{}
		for i := 0; i < 900; i++ {
			b.WriteString("--X\r\n")
			fmt.Fprintf(&b, "Content-Disposition: form-data; name=\"k%d\"\r\n", i)
			for h := 0; h < 11; h++ {
				fmt.Fprintf(&b, "X-P%02d: v\r\n", h)
			}
			b.WriteString("\r\nv\r\n")
		}
		b.WriteString("--X--\r\n")
		v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
		err := bp.ProcessRequest(strings.NewReader(b.String()), v, plugintypes.BodyProcessorOptions{
			Mime: "multipart/form-data; boundary=X", ArgumentLimit: limit, StoragePath: t.TempDir(),
		})
		if !errors.Is(err, bodyprocessors.ErrArgumentsLimit) {
			t.Fatalf("a flood of 10800 part headers did not trip the budget: %v", err)
		}
	})
}

// TestJSONArgumentFreeBodiesAreNotDenied asserts that a body carrying no
// arguments is not reported as truncated at nesting depths real clients send.
// Array lengths are metadata, so a body ModSecurity counts zero arguments for
// must not be denied by a rule written against REQBODY_ERROR.
//
// Since the v3.8.1 sync the length entries are charged to upstream's flatten
// byte budget (GHSA-6r3q-mjv7-xr8m), whose floor of 4096 bytes is outgrown by
// arrays nested about 64 levels deep (path length is quadratic in depth), so
// the former 100..1000 rows now end in a REQBODY_ERROR by design.
func TestJSONArgumentFreeBodiesAreNotDenied(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	for _, depth := range []int{10, 50} {
		t.Run(fmt.Sprintf("nested_arrays_%d", depth), func(t *testing.T) {
			body := strings.Repeat("[", depth) + strings.Repeat("]", depth)
			v := corazawaf.NewTransactionVariables(persistence.NoopEngine{})
			if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
				RequestBodyRecursionLimit: 1024,
				ArgumentLimit:             1000,
			}); err != nil {
				t.Errorf("a %d byte body carrying no arguments was reported as truncated: %v", len(body), err)
			}
			// Dropping the entries that do not fit still bounds what is stored.
			stored := 0
			for _, m := range v.ArgsPost().FindAll() {
				stored += len(m.Key()) + len(m.Value())
			}
			if maxStored := len(body) * 65; stored > maxStored {
				t.Errorf("stored %d bytes from a %d byte body, the budget allows %d", stored, len(body), maxStored)
			}
		})
	}
}
