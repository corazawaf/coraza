package main

import (
	"flag"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/proxy"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
)

func main() {
	configpath := flag.String("f", "/etc/coraza/rproxy.yml", "Path to config file")
	flag.Parse()
	fmt.Println("   _____ ____  _____             ______         ")
	fmt.Println("  / ____/ __ \\|  __ \\     /\\    |___  /   /\\    ")
	fmt.Println(" | |   | |  | | |__) |   /  \\      / /   /  \\   ")
	fmt.Println(" | |   | |  | |  _  /   / /\\ \\    / /   / /\\ \\  ")
	fmt.Println(" | |___| |__| | | \\ \\  / ____ \\  / /__ / ____ \\ ")
	fmt.Println("  \\_____\\____/|_|  \\_\\/_/    \\_\\/_____/_/    \\_\\")
	fmt.Println("          Web Application Firewall               ")
	fmt.Println("Preparing reverse proxy")
	dat, err := ioutil.ReadFile(*configpath)
	if err != nil {
		fmt.Print("Error reading config file: ")
		fmt.Print(err)
		fmt.Print("\n")
		return
	}
	fmt.Println("Configuration test passed!")
	config, err := proxy.ParseConfig([]byte(dat))
	if err != nil {
		fmt.Println("Error parsing configurations")
		fmt.Println(err)
		return
	}
	ps := proxy.ProxyServer{}
	err = ps.Init(config)
	if err != nil {
		log.Fatal(err)
	}
}
