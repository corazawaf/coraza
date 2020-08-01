package utils

import(
	"fmt"
	"time"
	"encoding/json"
	"strconv"
	"context"
	"errors"
    "github.com/go-redis/redis/v8"
)

/*
Important notes
Persistent collections are stored as collection-key, where key is the key to the collection, ex. an IP Address
Each persistent collection has it's own subkeys
Subkeys timeouts are stored as {keyname}_timeout

TODO
Add a thread to keep deleting timedout keys
*/
type PersistentCollection struct {
	collection string
	key string
	ttl int
	changed bool
	Vars map[string]string
	rc *redis.Client  
}

var rctx = context.Background()

func (c *PersistentCollection) Init(rc *redis.Client, collection string, key string) {
	c.rc = rc
	c.collection = fmt.Sprintf("col-%s-%s", collection, key)
	c.key = key
	err := c.Reload()
	if err != nil {
		c.New(rc, collection, key, 0)
	}
}

func (c *PersistentCollection) New(rc *redis.Client, collection string, key string, ttl int) {
	c.rc = rc
	reserved := []string{"SESSION", "IP"}
	if StringInSlice(collection, reserved){
		return 
	}
	c.collection = fmt.Sprintf("col-%s-%s", collection, key)
	c.ttl = ttl
	c.key = key
	timenow := strconv.FormatInt(time.Now().UnixNano(), 10)
	c.Vars = map[string]string{
		"CREATE_TIME": timenow,
		"IS_NEW": "1",
		"LAST_UPDATE_TIME": timenow,
		"TIMEOUT": "0",
		"UPDATE_COUNTER": "0",
		"UPDATE_RATE": "0",
	}
}

func (c *PersistentCollection) NewReserved(collection string, key string, ttl int) {
	c.collection = fmt.Sprintf("col-%s-%s", collection, key)
	c.ttl = ttl
	c.key = key
	timenow := strconv.FormatInt(time.Now().UnixNano(), 10)
	c.Vars = map[string]string{
		"CREATE_TIME": timenow,
		"IS_NEW": "1",
		"LAST_UPDATE_TIME": timenow,
		"TIMEOUT": "0",
		"UPDATE_COUNTER": "0",
		"UPDATE_RATE": "0",
	}
}


func (c *PersistentCollection) Reload() error{
	c.Vars = map[string]string{}
	val, _ := c.rc.Get(rctx, c.collection).Result()
	err := json.Unmarshal([]byte(val), &c.Vars)
	if err != nil {
		return err
	}
	return nil
}

func (c *PersistentCollection) Get(key string) string{
	f := c.Vars[key]
	timeout , err := strconv.ParseInt(c.Vars[key + "_timeout"], 10, 64)
	if err != nil{
		// TODO ?
		return f
	}

	if timeout < time.Now().UnixNano(){
		c.Delete(key)
		return ""
	}
	return f
}

func (c *PersistentCollection) Delete(key string) {
	delete(c.Vars, key)
	delete(c.Vars, key + "_timeout")
	c.Save()
}

func (c *PersistentCollection) SetTtl(key string, ttl int) {
	to := time.Now().UnixNano() + int64(ttl * 1000)
	c.Vars[key + "_timeout"] = strconv.FormatInt(to, 10)
}

func (c *PersistentCollection) Set(key string, value string) error{
	readonly := []string{"CREATE_TIME", "IS_NEW", "LAST_UPDATE_TIME", "TIMEOUT", "UPDATE_COUNTER", "UPDATE_RATE"}
	if StringInSlice(key, readonly){
		return errors.New("Attempting to update readonly var for persistent collection")
	}
	c.changed = true
	c.Vars[key] = value
	c.Save()
	return nil
}

func (c *PersistentCollection) Save() {
	if c.changed{
		count , _:= strconv.Atoi(c.Vars["UPDATE_COUNTER"])
		newcount := strconv.Itoa(count+1)
		timenow := strconv.FormatInt(time.Now().UnixNano(), 10)
		c.Vars["UPDATE_COUNTER"] = newcount
		c.Vars["LAST_UPDATE_TIME"] = timenow
	}
	js, err := json.Marshal(c.Vars)
	if err != nil{
		fmt.Println("Error serializing collection " + c.key)
	}
	c.rc.Set(rctx, c.collection, js, 0)
	c.Reload()
}