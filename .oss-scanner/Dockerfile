# Build environment for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this image with the repository checkout as the build context, then
# analyses it with no network access, so everything the build and the tests need is fetched
# here. Keep the Go version aligned with .github/workflows/regression.yml.
FROM golang:1.26-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Every module in the workspace: the engine, the example server and the CRS regression suite
# (which pulls OWASP CRS v4 and go-ftw as Go modules). testing/modsecurity needs the
# libmodsecurity C library and is only downloaded, not built.
RUN go mod download

# Build the engine, the mage runner and the example server. A failing step fails the build.
RUN go build ./... \
    && go run mage.go -l >/dev/null \
    && (cd examples/http-server && go build -o /src/build/http-server .)

# Compile (not run) the test binaries under every build tag CI uses, plus the race detector,
# so the whole matrix is runnable offline from the Go build cache: see "Running tests" in AGENTS.md.
RUN go vet ./... \
    && for tags in "" coraza.no_memoize coraza.rule.multiphase_evaluation coraza.rule.no_regex_multiline \
                   coraza.rule.case_sensitive_args_keys coraza.rule.mandatory_rule_id_check \
                   coraza.rule.rx_prefilter no_fs_access "no_fs_access,coraza.no_memoize"; do \
         go test -tags="$tags" -run '^$' ./... >/dev/null || exit 1; \
       done \
    && go test -race -run '^$' ./internal/corazawaf/ >/dev/null \
    && (cd testing/coreruleset \
        && go test -run '^$' ./... >/dev/null \
        && go test -tags=coraza.rule.multiphase_evaluation -run '^$' ./... >/dev/null)

# `go run mage.go lint` fetches golangci-lint, addlicense and gosimports with `go run pkg@version`
# (versions pinned in magefile.go); running it once here caches them so `go run mage.go check`
# works offline. It also regenerates and tidies, which is a no-op on a clean checkout. A
# failure here fails the build: the tools it did not get to are unreachable once the network
# is gone, and a lint failure on a clean checkout is a CI failure anyway.
RUN go run mage.go lint

# Run the cheap tests so you know the image works, but do not let a failing test abort the build.
# As root, TestConcurrentWriterFailsOnInit and TestSerialWriterFailsOnInitForUnexistingFile fail
# by construction (they expect /unexisting.log to be unwritable); see threat_model.md.
RUN (go test ./... && cd testing/coreruleset && go test ./...) \
    || echo "WARNING: go test reported failures"

# The scanner runs the image with no network. `go run pkg@version` (how mage lint invokes its
# tools) still resolves the version through the proxy even when the module is cached, so from
# here on serve the module cache itself as the proxy. Every module in it was fetched and
# checksum-verified by the steps above, which is why the checksum database can be off.
ENV GOPROXY=file:///go/pkg/mod/cache/download \
    GOSUMDB=off
