package main
import(
	"github.com/jptosso/coraza/pkg/cwm"
	"flag"
	"os"
	"fmt"
)

func main(){
	register := flag.String("register", "", "Path to WAF Project")
	status := flag.Bool("status", false, "Print services status")
	restart := flag.String("restart", "", "Gracefully restart application by id")
	start := flag.String("start", "", "Gracefully restart application by id")
	cfpath := flag.String("f", "/etc/coraza/cwm.yaml", "Change the configuration path")
	flag.Parse()

	config := &cwm.ConfigFile{}
	err := config.Init(*cfpath)
	if err != nil {
		fmt.Println("Cannot open configuration file.", err)
		os.Exit(1)
	}
	if len(config.GetProxies()) == 0{
		fmt.Println("There are not applications registered.")
		return
	}


	if *status{
		s := &cwm.Status{}
		s.Init(config)
		s.Print()
	}
	if *register != ""{

	}

	if *restart != ""{

	}

	if *start != ""{
		fmt.Println("Attempting to start " + *start)
		proxy := config.GetProxyFileById(*start)
		if proxy == ""{
			fmt.Printf("The application %s does not exist.\n", *start)
			os.Exit(1)
			return
		}
		cwm.InitService("/tmp/waf-rproxy", proxy, config.Cwm.User, config.Cwm.Group)
	}
}