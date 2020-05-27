package cwm
//Copied from https://github.com/struCoder/pidusage

import (
	"errors"
	"io/ioutil"
	"math"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// SysInfo will record cpu and memory data
type SysInfo struct {
	CPU    float64
	Memory float64
}

// Stat will store CPU time struct
type Stat struct {
	utime  float64
	stime  float64
	cutime float64
	cstime float64
	start  float64
	rss    float64
	uptime float64
}

type fn func(int) (*SysInfo, error)

var fnMap map[string]fn
var platform string
var history map[int]Stat
var historyLock sync.Mutex
var eol string

func wrapper(statType string) func(pid int) (*SysInfo, error) {
	return func(pid int) (*SysInfo, error) {
		return stat(pid, statType)
	}
}
func init() {
	platform = runtime.GOOS
	if eol = "\n"; strings.Index(platform, "win") == 0 {
		platform = "win"
		eol = "\r\n"
	}
	history = make(map[int]Stat)
	fnMap = make(map[string]fn)
	fnMap["darwin"] = wrapper("ps")
	fnMap["sunos"] = wrapper("ps")
	fnMap["freebsd"] = wrapper("ps")
	fnMap["aix"] = wrapper("ps")
	fnMap["linux"] = wrapper("proc")
	fnMap["netbsd"] = wrapper("proc")
	fnMap["win"] = wrapper("win")
}
func formatStdOut(stdout []byte, userfulIndex int) []string {
	infoArr := strings.Split(string(stdout), eol)[userfulIndex]
	ret := strings.Fields(infoArr)
	return ret
}

func parseFloat(val string) float64 {
	floatVal, _ := strconv.ParseFloat(val, 64)
	return floatVal
}

func stat(pid int, statType string) (*SysInfo, error) {
	sysInfo := &SysInfo{}
	_history := history[pid]
	if statType == "ps" {
		args := "-o pcpu,rss -p"
		if platform == "aix" {
			args = "-o pcpu,rssize -p"
		}
		stdout, _ := exec.Command("ps", args, strconv.Itoa(pid)).Output()
		ret := formatStdOut(stdout, 1)
		if len(ret) == 0 {
			return sysInfo, errors.New("Can't find process with this PID: " + strconv.Itoa(pid))
		}
		sysInfo.CPU = parseFloat(ret[0])
		sysInfo.Memory = parseFloat(ret[1]) * 1024
	} else if statType == "proc" {
		// default clkTck and pageSize
		var clkTck float64 = 100
		var pageSize float64 = 4096

		uptimeFileBytes, err := ioutil.ReadFile(path.Join("/proc", "uptime"))
		uptime := parseFloat(strings.Split(string(uptimeFileBytes), " ")[0])

		clkTckStdout, err := exec.Command("getconf", "CLK_TCK").Output()
		if err == nil {
			clkTck = parseFloat(formatStdOut(clkTckStdout, 0)[0])
		}

		pageSizeStdout, err := exec.Command("getconf", "PAGESIZE").Output()
		if err == nil {
			pageSize = parseFloat(formatStdOut(pageSizeStdout, 0)[0])
		}

		procStatFileBytes, err := ioutil.ReadFile(path.Join("/proc", strconv.Itoa(pid), "stat"))
		splitAfter := strings.SplitAfter(string(procStatFileBytes), ")")

		if len(splitAfter) == 0 || len(splitAfter) == 1 {
			return sysInfo, errors.New("Can't find process with this PID: " + strconv.Itoa(pid))
		}
		infos := strings.Split(splitAfter[1], " ")
		stat := &Stat{
			utime:  parseFloat(infos[12]),
			stime:  parseFloat(infos[13]),
			cutime: parseFloat(infos[14]),
			cstime: parseFloat(infos[15]),
			start:  parseFloat(infos[20]) / clkTck,
			rss:    parseFloat(infos[22]),
			uptime: uptime,
		}

		_stime := 0.0
		_utime := 0.0
		if _history.stime != 0 {
			_stime = _history.stime
		}

		if _history.utime != 0 {
			_utime = _history.utime
		}
		total := stat.stime - _stime + stat.utime - _utime
		total = total / clkTck

		seconds := stat.start - uptime
		if _history.uptime != 0 {
			seconds = uptime - _history.uptime
		}

		seconds = math.Abs(seconds)
		if seconds == 0 {
			seconds = 1
		}

		historyLock.Lock()
		history[pid] = *stat
		historyLock.Unlock()
		sysInfo.CPU = (total / seconds) * 100
		sysInfo.Memory = stat.rss * pageSize
	}
	return sysInfo, nil

}

// GetStat will return current system CPU and memory data
func GetStat(pid int) (*SysInfo, error) {
	sysInfo, err := fnMap[platform](pid)
	return sysInfo, err
}