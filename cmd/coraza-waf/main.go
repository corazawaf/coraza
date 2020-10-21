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
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var grpcsrv *grpcServer

func main() {
	cfgmode := flag.String("m", "skipper", "Configuration Mode, skipper or grpc")
	cfgfile := flag.String("f", "", "Configurations path")
	pidfile := flag.String("pid", "/tmp/coraza.pid", "Pid file location")
	flag.Parse()

	err := writePidFile(*pidfile)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	closeHandler(*pidfile)

	if *cfgmode == "grpc" {
		grpcsrv = &grpcServer{}
		err := grpcsrv.Init(*cfgfile)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("Running grpc server")
		log.Fatal(grpcsrv.Serve())
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

func writePidFile(pidFile string) error {
	if piddata, err := ioutil.ReadFile(pidFile); err == nil {
		if pid, err := strconv.Atoi(string(piddata)); err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				// Send SIGKILL
				if err := process.Signal(syscall.Signal(0)); err == nil {
					// We only get an error if the pid isn't running, or it's not ours.
					return fmt.Errorf("pid already running: %d", pid)
				}
			}
		}
	}
	// If we get here, then the pidfile didn't exist,
	// or the pid in it doesn't belong to the user running this app.
	return ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0664)
}

func closeHandler(pidfile string) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Info("Closing Coraza WAF")
		err := os.Remove(pidfile)
		if err != nil {
			log.Error("Failed to remove pid file")
			os.Exit(1)
		}
		grpcsrv.Close()
		os.Exit(0)
	}()
}
