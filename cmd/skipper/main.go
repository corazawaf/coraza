// Copyright 2020 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
