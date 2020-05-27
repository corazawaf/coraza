package cwm

import(
	// #include <unistd.h>
	"C"
	"github.com/olekukonko/tablewriter"
	"os"
	"strconv"
	"fmt"
	"io/ioutil"
	"strings"
)

type Status struct {
	config *ConfigFile
}


func (s *Status) Init(config *ConfigFile){
	s.config = config
}

func (s *Status) Print(){
	data := s.mapProxies()
	//sysInfo, err := pidusage.GetStat(os.Process.Pid)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Id", "Application", "Status", "Health", "Port", "Memory", "CPU"})
	table.SetBorder(true)                                // Set Border to false

	table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlackColor})

	table.AppendBulk(data)
	table.Render()
}

func (s *Status) mapProxies() [][]string{
	data := [][]string{}
	totalmemory := (float64)(C.sysconf(C._SC_PHYS_PAGES)*C.sysconf(C._SC_PAGE_SIZE))
	for _, p := range s.config.GetProxies() {
		app := p.Application
		arr := []string{app.Id, app.Hostnames[0], "Offline", "Fail", strconv.Itoa(p.Port),	"-", "-"}
		pid, err := ioutil.ReadFile(p.PidPath)
		if err != nil{
			data = append(data, arr)
			continue
		}
		arr[2] = "Online"
		arr[3] = "Ok"
		//PID files contains a \n at the end
		pidint, _ := strconv.Atoi(strings.TrimSpace(string(pid)))
		sysInfo, _ := GetStat(pidint)
		arr[5] = fmt.Sprintf("%.1fmb (%.2f%%)", (sysInfo.Memory/1024)/1024, (sysInfo.Memory*100)/totalmemory)
		arr[6] = fmt.Sprintf("%.2f%%", sysInfo.CPU)
		data = append(data, arr)
	}
	return data
}