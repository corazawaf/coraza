package loggers

import (
	"bufio"
	"fmt"
	"os"
)

type SimpleLogger struct {
	file   *os.File
	writer *io.Writter
}

func (sl *SimpleLogger) New(file string, dir string, filemod int, dirmode int) {
	var err error
	sl.file, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	sl.writter = bufio.NewWriter(sl.file)
}

func (sl *SimpleLogger) Write(log Log) {
	opts := []string{
		"ddd MMM DD HH:mm:ss.S YYYY", // Timestamp
		"ip address",
		"error",
		"operator",
		"params",
		"variable",
		"rules",
		"",
	}
	variable := ""
	clientIp := ""
	status := 0
	phase := 0
	id := ""
	url := ""
	severity := ""
	ts := "ddd MMM DD HH:mm:ss.S YYYY"
	for _, r := range log.Rules {
		opts["rules"] += fmt.Sprintf("[id \"%d\"] ", r.Id)
	}
	data := fmt.Sprintf("[%s] [error] [client %s] ModSecurity: Access denied with code 505 (phase 1). Match of \"rx ^HTTP/(0.9|1.[01])$\" against \"REQUEST_PROTOCOL\" required. %s %s [severity \"%s\"] [uri \"%s\"] [unique_id \"%s\"]\n", opts)
	sl.writter.WriteString(data)
}

func (sl *SimpleLogger) Close() {
	sl.file.Close()
	sl.writter.Flush()
}
