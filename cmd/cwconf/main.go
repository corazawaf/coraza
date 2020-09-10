package main

import(
	"flag"
	"os"
	"fmt"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
)

func main(){
	file := flag.String("f", "", "path of WAF config file to test")
	flag.Parse()

	if *file == ""{
		fmt.Println("-f is mandatory.")
		os.Exit(1)
	}

	waf := &engine.Waf{}
	waf.Init()

	p := &parser.Parser{}
	p.Init(waf)

	if p.FromFile(*file) != nil{
		fmt.Println("Exited with errors")
		os.Exit(11)
	}
	fmt.Println("Exited without errors.")
}