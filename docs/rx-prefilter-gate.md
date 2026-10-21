# SecRxPreFilter gate

`SecRxPreFilter On` makes the `@rx` operator skip a regular expression when a literal its
pattern needs is missing from the input. It is experimental in Coraza. A bug in it hides a
detection without any error: the rule simply does not match. The gate proves, for one ruleset
and one build of this fork, that `On` and `Off` give the same answer. Enable `On` on a
server only when the gate passed for the ruleset and the fork tag that server runs.

## Running it

```bash
bash scripts/rx-prefilter-gate.sh --rules <dir with the ruleset's *.conf>
bash scripts/rx-prefilter-gate.sh --rules <dir> --mode full  # adds the end-to-end replay
bash scripts/rx-prefilter-gate.sh --rules <dir> --audit-logs <file or dir>   # adds production requests
```

It needs Go and a checkout of the fork at the tag the product pins. The script takes a
directory and knows nothing about where the ruleset comes from: whoever builds or publishes the
ruleset unpacks it and passes the directory. Exit status 0 means
`On` and `Off` agree; 1 means they disagree or a check could not run. `build/rx-prefilter-gate/summary.txt`
holds the short result and ends with `RESULT: PASS` or `RESULT: FAIL`.

| Mode | What it does | Time |
| --- | --- | --- |
| `pattern` | Takes every `@rx` pattern of the ruleset, builds the operator with and without the prefilter, feeds both inputs generated from the pattern itself and requires the same answer. | seconds (7 s for 1,426 patterns and 3 million inputs), plus compiling |
| `full` | `pattern`, then replays the CRS regression corpus, each payload carried six ways (as written, query string, urlencoded form, JSON, a padded 28 KB body, echoed in the response), through the bundled CRS and through the ruleset, and compares the matched rule ids and the interruption of every transaction. | about 10 min (22,427 requests, three configurations) |

The ruleset build should run `pattern` on every candidate ruleset: it is cheap enough to run
on each daily rule edit, before the ruleset is published. The workflow `rx-prefilter-gate.yml` runs `full` on every `v*-cl*`
tag and can be started by hand. It fetches the ruleset from the https URL in the repository
variable `RX_PREFILTER_RULESET_URL` (a zip of the `*.conf` files; `RX_PREFILTER_RULESET_SHA256`
pins it) or from the `ruleset_url` input, and fails when it has neither. The repository variable
`RX_PREFILTER_REMOVE_IDS` sets `CORAZA_RX_PARITY_REMOVE_IDS` (see Knobs).

## Replaying production requests

`--audit-logs <file or directory>` replays the requests in JSON audit logs
(`SecAuditLogFormat JSON`, `*.gz` unzipped) through the ruleset, Off against On, in
`DetectionOnly` and in `On`. A request is replayed as logged: method, URI, headers and the
body. The body is in the log only with part C in `SecAuditLogParts`. Part C is the request
body, passwords included, in a plain-text log: switch it on only on the servers picked for the
replay, for the length of the run, and delete those logs afterwards. The integration may log
only the start of a body, and a ruleset can remove part C itself (`ctl:auditLogParts`), for
example for file uploads and for requests whose body did not parse. The summary counts the requests logged
without a body and with only the start of one; Off and On are still compared on what survived,
but file-upload rules cannot be replayed from audit logs (the pattern check and the
end-to-end replay cover them). The replay also reports how many of the rules the log lists
matched again with the prefilter off, for the requests with their whole body. A rule that does
not is not a prefilter finding (the ruleset can differ from the one that logged it, and
response-phase rules never ran), but a large share means the replay is not reading the log
properly.

`--mode full` runs a self-check first: it writes an audit log with the ruleset and the CRS
corpus as traffic, replays that, and fails unless the replay reads it back and reproduces the
rules it lists. The report of a real replay holds request lines, which can carry customer
data: keep it inside the company.

## What it does not cover

`pattern` and `full` use generated and corpus inputs; only `--audit-logs` uses production
traffic, and only the requests that were logged. None of it says anything about performance.
A pattern the generator cannot build matching inputs for is compared on fewer inputs; the
`inputs compared, N of them matched by the regex` line shows how many it could.

## Knobs

`CORAZA_PREFILTER_SAMPLES` (inputs per pattern, default 300), `MIN_PATTERNS` (fail if fewer
patterns than this are found, default 100), `OUT` (output directory),
`CORAZA_RX_PARITY_REMOVE_IDS` (rule ids, separated by commas or spaces, removed from the ruleset
in the replays: a rule whose match is random, such as one that samples traffic by `UNIQUE_ID`,
fires on a different request in every run and would show as a difference between Off and On). `--limit N` shortens the
replay to the first N corpus requests for a smoke run.
