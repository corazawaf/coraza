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
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper"
	"github.com/zalando/skipper/config"
	"os"
)

func main() {
	cfgmode := flag.String("m", "skipper", "Configuration Mode, skipper or grpc")
	cfgfile := flag.String("f", "", "Configurations path")
	flag.Parse()
	if *cfgmode == "grpc" {
		server := &grpcServer{}
		err := server.Init(*cfgfile)
		if err != nil{
			log.Fatal(err)
		}
		log.Info("Running grpc server")
		log.Fatal(server.Serve())
	} else if *cfgmode == "skipper" {
		initSkipper(*cfgfile)
	} else {
		log.Fatal("Invalid operation mode -m")
	}

}

func initSkipper(cfgfile string) {
	os.Args = []string{os.Args[0], "-config-file=" + cfgfile}

	cfg := config.NewConfig()
	if err := cfg.Parse(); err != nil {
		log.Fatalf("Error processing config: %s", err)
	}

	opts := cfg.ToOptions()

	opts.CustomFilters = append(opts.CustomFilters, &CorazaSpec{})
	if cfg.ApplicationLog != "" {
		fmt.Println("Coraza WAF will be logging to log files.")
	} else {
		fmt.Println("Logging to stdout")
	}
	log.Fatal(skipper.Run(opts))
}
