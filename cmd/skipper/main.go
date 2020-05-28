package main

import (
    "log"
    "github.com/zalando/skipper"
    "github.com/zalando/skipper/filters"
    "github.com/zalando/skipper/config"
    _"github.com/zalando/skipper/routing"
    cskipper"github.com/jptosso/coraza-waf/pkg/skipper"
)

func main() {
    cfg := config.NewConfig()
    if err := cfg.Parse(); err != nil {
        log.Fatalf("Error processing config: %s", err)
    }
    opts := cfg.ToOptions()
    opts.CustomFilters = []filters.Spec{&cskipper.CorazaSpec{}}
    log.Fatal(skipper.Run(opts))
}