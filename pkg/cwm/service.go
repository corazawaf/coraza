package cwm
import(
    "fmt"
    "os"
    "strconv"
    "syscall"
    "strings"
    osuser"os/user"

)

func InitService(wafbin string, wafconfig string, username string, groupname string) error{
    rpipe, wpipe, err := os.Pipe()
    if err != nil {
      fmt.Printf("Unable to get read and write files: %s\n", err)
      os.Exit(-2)
    }
    defer rpipe.Close()
    defer wpipe.Close()
    uid := os.Getuid()
    gid := os.Getgid()
    if username != ""{
    	user, err := osuser.Lookup(username)
    	if err != nil{
    		return err
    	}
    	uid, _ = strconv.Atoi(user.Uid)
    }
    if groupname != ""{
	    group, err := osuser.LookupGroup(groupname)
    	if err != nil{
    		return err
    	}	    
	    gid, _ = strconv.Atoi(group.Gid)
    }

    fork := NewForkProcess(rpipe, wpipe, wpipe, uint32(uid), uint32(gid), "/")
    args := []string{wafbin, "-f ", wafconfig}
    fmt.Println("forking", strings.Join(args, " "))
    err = fork.Exec(true, wafbin, args)

    if err != nil {
      fmt.Printf("Unable to fork: %s\nThis problem is probably related with the user and group.\n", err)
      return err
    }
    fmt.Printf("Run `ps axuf | grep '%s'` to see the process running\n", wafbin)
    return nil
}

func StopService(pid int) error{
	//TODO validate that the process exited
    return syscall.Kill(pid, 25)
}