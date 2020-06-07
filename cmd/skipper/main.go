package main

import (
    "log"
    "fmt"
    "github.com/zalando/skipper"
    "github.com/zalando/skipper/filters"
    "github.com/zalando/skipper/config"
    _"github.com/zalando/skipper/routing"
    cskipper"github.com/jptosso/coraza-waf/pkg/skipper"
)

func main() {
    fmt.Println("   _____ ____  _____             ______         ")
    fmt.Println("  / ____/ __ \\|  __ \\     /\\    |___  /   /\\    ")
    fmt.Println(" | |   | |  | | |__) |   /  \\      / /   /  \\   ")
    fmt.Println(" | |   | |  | |  _  /   / /\\ \\    / /   / /\\ \\  ")
    fmt.Println(" | |___| |__| | | \\ \\  / ____ \\  / /__ / ____ \\ ")
    fmt.Println("  \\_____\\____/|_|  \\_\\/_/    \\_\\/_____/_/    \\_\\")
    fmt.Println("          Web Application Firewall - Skipper")
    fmt.Println("Preparing reverse proxy")    
    cfg := config.NewConfig()
    if err := cfg.Parse(); err != nil {
        log.Fatalf("Error processing config: %s", err)
    }
    opts := cfg.ToOptions()
    opts.CustomFilters = []filters.Spec{&cskipper.CorazaSpec{}}
    log.Fatal(skipper.Run(opts))
}