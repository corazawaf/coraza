package utils

import(
	"strings"
	"bufio"
	"os"
)

func ParseConfig(filepath string) (map[string]string, error){
    file, err := os.Open(filepath)
    res := map[string]string{}
    if err != nil {
        return res, err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    var line string
    for scanner.Scan() {
        line = scanner.Text()
        if len(line) == 0 || line[0] == '#'{
        	continue
        }
        spl := strings.SplitN(line, "=", 2)
        res[string(spl[0])] = string(spl[1])
    }

    if err := scanner.Err(); err != nil {
        return res, err
    }
    return res, nil
}