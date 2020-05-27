package main

import(
    "github.com/jptosso/coraza-waf/pkg/rproxy"
	"fmt"   
    "io/ioutil"
    "flag"
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
	hs := rproxy.HttpServer{}
	hs.Init()
	dat, err := ioutil.ReadFile(*configpath)
	if err != nil{
		fmt.Print("Error reading config file: ")
		fmt.Print(err)
		fmt.Print("\n")
		return
	}
	err = rproxy.ParseConfig(&hs, []byte(dat))
	if err != nil{
		fmt.Println("Error parsing configurations")
		fmt.Println(err)
		return
	}
	fmt.Println("Configuration test passed!")
    hs.Start()
}
