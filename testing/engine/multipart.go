// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "airween",
		Description: "Test against multipart payloads",
		Enabled:     true,
		Name:        "multipart.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "multipart",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php?id=12345",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="_msg_body"

Hi Martin,

this is the test message.

Regards,

--
airween
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100, 200, 250, 300},
							NonTriggeredRules: []int{150, 200002},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecRule ARGS_POST:_msg_body "Hi" "id:100, phase:2,log"
SecRule ARGS_GET:_msg_body "Hi" "id:150, phase:2,log"
SecRule ARGS:_msg_body "@rx Hi Martin," "id:200, phase:2,log"
SecRule MULTIPART_PART_HEADERS:_msg_body "Content-Disposition" "id:250, phase:2, log"
SecRule MULTIPART_PART_HEADERS "Content-Disposition" "id:300, phase:2, log"
SecRule REQBODY_ERROR "!@eq 0" \
  "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
`,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "MULTIPART_STRICT_ERROR rule triggered",
		Enabled:     true,
		Name:        "multipart_error.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "multipart error invalid 0x0E",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php?id=1",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
\x0EContent-Disposition: form-data; name="_msg_body"

The Content-Disposition header contains an invalid character (0x0E).
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002, 200003},
						},
					},
				},
			},
		},
		{
			Title: "multipart error invalid 0x20",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-\x20Disposition: form-data; name="file"; filename="1.php"

0x20 character is expected to be the last invalid character before the valid range.
Therefore, the parser should fail and raise MULTIPART_STRICT_ERROR.
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002, 200003},
						},
					},
				},
			},
		},
		{
			Title: "multipart error duplicate boundary parameter",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000; boundary=--0001",
							},
							Data: `
----0000
Content-Disposition: form-data; name="_msg_body"

Duplicate boundary parameters make the Content-Type header ambiguous.
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002},
						},
					},
				},
			},
		},
		{
			Title: "multipart error trailing junk parameter",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI: "/test.php",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000; junk",
							},
							Data: `
----0000
Content-Disposition: form-data; name="_msg_body"

A trailing junk parameter still selects the MULTIPART processor, but
the malformed header is rejected when the body is actually parsed.
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200002},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule REQBODY_ERROR "!@eq 0" \
  "id:'200002', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400, msg:'Multipart request body failed strict validation."
  `,
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "fzipi",
		Description: "Content-Disposition filename* precedence, and the strict-error signals around it",
		Enabled:     true,
		Name:        "multipart_filename_star.yaml",
	},
	Tests: []profile.Test{
		{
			// GHSA-3wr7-993q-jrff: the real filename rides in filename* under a
			// charset the Go stdlib refuses to decode, with a benign decoy in
			// the plain filename. Rule 933110 is CRS's own PHP-upload rule,
			// transformations included, to show FILES carries what the backend
			// would actually use.
			Title: "filename* under a non-utf-8 charset reaches FILES",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename="safe.jpg"; filename*=iso-8859-1''shell.php

<?php system($_GET['c']); ?>
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{933110},
							NonTriggeredRules: []int{200003, 200004},
						},
					},
				},
			},
		},
		{
			// Making filename* unconditionally authoritative closes the case
			// above but relocates the same bypass to the opposite payload
			// shape: swap which field carries the real name and a backend
			// that resolves the plain "filename" instead would still be
			// missed if only one reading reached FILES. Both readings are
			// kept so 933110 fires either way.
			Title: "fields swapped: real name in plain filename, decoy in filename* -- still reaches FILES",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename="shell.php"; filename*=iso-8859-1''safe.jpg

<?php system($_GET['c']); ?>
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{933110},
							NonTriggeredRules: []int{200003, 200004},
						},
					},
				},
			},
		},
		{
			// A percent-encoded separator is decoded by every backend that
			// implements RFC 5987, so FILES has to carry the decoded name for
			// an extension rule to see it.
			Title: "percent-encoded filename* still reaches FILES decoded",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename="safe.jpg"; filename*=UTF-8''shell%2Ephp

<?php system($_GET['c']); ?>
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{933110},
							NonTriggeredRules: []int{200003, 200004},
						},
					},
				},
			},
		},
		{
			Title: "a filename* that is not charset'language'value raises MULTIPART_STRICT_ERROR",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename*=noquoteshere

file content
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200003},
							NonTriggeredRules: []int{933110, 200004},
						},
					},
				},
			},
		},
		{
			// The advisory tells operators to police the declared charset with
			// an allowlist rule of their own. That rule has to stay quiet on
			// ordinary parts: the charset collection is only populated when a
			// part actually carries a filename*, so a plain upload leaves
			// nothing for "!@within" to match. Setting it to an empty string
			// for every part instead would make the anchored-regex form of the
			// rule fire on every form field. Both forms are checked because
			// they disagree: "" is trivially within any haystack, so the
			// "!@within" form stays quiet either way, while "!@rx ^(...)$"
			// does not match "" and so fires. Only the regex form actually
			// distinguishes the two behaviours.
			Title: "the recommended charset allowlist rule stays quiet without filename*",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename="holiday.jpg"

file content
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{200010, 200011},
						},
					},
				},
			},
		},
		{
			// And it has to fire when a filename* declares a charset outside
			// the allowlist, or it protects nothing.
			Title: "the recommended charset allowlist rule fires on an unlisted charset",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename*=shift_jis''shell.php

file content
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200010, 200011},
						},
					},
				},
			},
		},
		{
			// A filename* that declares no charset at all. The advisory used
			// to recommend "!@within", which never fires here: @within treats
			// its parameter as the haystack, so an empty value is trivially
			// contained and the negation is always false. The anchored regex
			// catches it. This is why the advisory recommends the regex form.
			Title: "an empty charset is caught by the regex allowlist, not by @within",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename*=''shell.php

file content
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200011},
							NonTriggeredRules: []int{200010},
						},
					},
				},
			},
		},
		{
			// RFC 5987 does not permit filename* to be a quoted-string. Coraza
			// still unwraps it (so FILES/933110 sees what a backend such as
			// Go's mime.ParseMediaType resolves), but the quoting itself is
			// invalid and must not be absorbed silently.
			Title: "a quoted filename* raises MULTIPART_INVALID_QUOTING but still reaches FILES",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename*="UTF-8''shell.php"

<?php system($_GET['c']); ?>
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200003, 200005, 933110},
							NonTriggeredRules: []int{200004},
						},
					},
				},
			},
		},
		{
			Title: "a repeated filename parameter raises MULTIPART_DUPLICATE_PART_HEADER",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename="safe.jpg"; filename="shell.php"

file content
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{200003, 200004},
							NonTriggeredRules: []int{933110},
						},
					},
				},
			},
		},
		{
			// M4tteoP's review: MULTIPART_INVALID_QUOTING was never defaulted
			// to "0" the way MULTIPART_DUPLICATE_PART_HEADER is, so logdata
			// referencing it (as coraza.conf-recommended's rule 200003 does)
			// printed an empty value here instead of "0" for a part that
			// never had a quoted filename* at all.
			Title: "MULTIPART_INVALID_QUOTING defaults to 0 without a quoted filename*",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Host":         "www.example.com",
								"Content-Type": "multipart/form-data; boundary=--0000",
							},
							Data: `
----0000
Content-Disposition: form-data; name="upload"; filename="holiday.jpg"

file content
----0000--
`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{200012},
							LogContains:    "MULTIPART_INVALID_QUOTING=0",
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecRule FILES|REQUEST_HEADERS:X-Filename "@rx .*\.ph(?:p\d*|tml|ar|ps|t|pt)\.*$" \
    "id:933110,phase:2,block,capture,t:none,t:lowercase,t:removeWhitespace,msg:'PHP Injection Attack: PHP Script File Upload Found'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,pass,msg:'Multipart request body failed strict validation'"
SecRule MULTIPART_DUPLICATE_PART_HEADER "@eq 1" \
    "id:'200004',phase:2,t:none,log,pass,msg:'Multipart part repeats a header or a Content-Disposition parameter'"
SecRule MULTIPART_INVALID_QUOTING "@eq 1" \
    "id:'200005',phase:2,t:none,log,pass,msg:'filename* was wrapped in a quoted-string'"
SecRule MULTIPART_FILENAME_CHARSET "!@within utf-8,iso-8859-1,us-ascii" \
    "id:'200010',phase:2,t:none,t:lowercase,log,pass,msg:'filename* declares a charset outside the allowlist'"
SecRule MULTIPART_FILENAME_CHARSET "!@rx ^(?:utf-8|iso-8859-1|us-ascii)$" \
    "id:'200011',phase:2,t:none,t:lowercase,log,pass,msg:'same allowlist, anchored-regex form'"
SecRule REQBODY_PROCESSOR "@streq MULTIPART" \
    "id:'200012',phase:2,t:none,log,pass,logdata:'MULTIPART_INVALID_QUOTING=%{MULTIPART_INVALID_QUOTING}'"
`,
})

// SecRequestBodyLimit 150 cuts the first two bodies below inside a part's
// content, where the multipart reader returns io.ErrUnexpectedEOF: the file
// part's headers are 89 bytes and the form field's are 46, so the cut lands 61
// and 104 bytes into their values. The two tests cover the file and the
// form-field branches. The third body is exactly 150 bytes and arrives already
// cut: it reaches the limit, so INBOUND_DATA_ERROR is set, but nothing is dropped.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "M4tteoP",
		Description: "a multipart body cut by ProcessPartial at the body limit does not raise MULTIPART_STRICT_ERROR",
		Enabled:     true,
		Name:        "multipart_process_partial.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "a file part cut inside its content by the limit is inspected, not rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "multipart/form-data; boundary=a",
							},
							Data: "--a\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\nContent-Type: text/plain\n\n" +
								"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n--a--\n",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100, 101},
							NonTriggeredRules: []int{200002, 200003},
						},
					},
				},
			},
		},
		{
			Title: "a form field cut inside its value by the limit is inspected, not rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "multipart/form-data; boundary=a",
							},
							Data: "--a\nContent-Disposition: form-data; name=\"t\"\n\n" +
								"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n--a--\n",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{100, 102},
							NonTriggeredRules: []int{200002, 200003},
						},
					},
				},
			},
		},
		{
			Title: "a form field that arrives cut, in a body exactly at the limit, is rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/upload",
							Method: "POST",
							Headers: map[string]string{
								"Content-Type": "multipart/form-data; boundary=a",
							},
							Data: "--a\nContent-Disposition: form-data; name=\"t\"\n\n" +
								"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{100, 200003},
							Interruption: &profile.ExpectedInterruption{
								Status: 400,
								RuleID: 200003,
								Action: "deny",
							},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 150
SecRequestBodyLimitAction ProcessPartial
SecRule INBOUND_DATA_ERROR "@eq 1" "id:100,phase:2,t:none,log,pass"
SecRule FILES "@streq x.txt" "id:101,phase:2,t:none,log,pass"
SecRule ARGS_POST:t "@rx ^B{104}$" "id:102,phase:2,t:none,log,pass"
SecRule REQBODY_ERROR "!@eq 0" \
    "id:'200002',phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation.'"
`,
})
