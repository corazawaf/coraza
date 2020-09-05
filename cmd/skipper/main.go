package main

import (
	"fmt"
	"log"

	skfilter "github.com/jptosso/coraza-waf/pkg/skipper"
	"github.com/zalando/skipper"
	"github.com/zalando/skipper/config"
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
	if cfg.ConfigFile == "" {
		cfg.ConfigFile = "/etc/coraza-waf/skipper.yaml"
	}
	if cfg.RoutesFile == "" {
		cfg.RoutesFile = "/etc/coraza-waf/routes.eskip"
	}
	opts := cfg.ToOptions()

	opts.CustomFilters = append(opts.CustomFilters, &skfilter.CorazaSpec{})
	log.Fatal(skipper.Run(opts))
}
