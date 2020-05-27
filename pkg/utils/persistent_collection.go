package utils

import(
	"fmt"
	"time"
	"encoding/json"
	"strconv"
)

type PersistentCollection struct {
	collection string
	key string
	ttl int
	changed bool
	Vars map[string]string
}

func (c *PersistentCollection) Init(collection string, key string) {
	c.collection = fmt.Sprintf("col-%s-%s", collection, key)
	c.key = key
	c.Vars = map[string]string{}
	val, _ := RedisClient.Get(Ctx, key).Result()
	err := json.Unmarshal([]byte(val), &c.Vars)
	if err != nil {
		//fmt.Println("ERROR PROCESSING COLLECTION " + key)
		RedisClient.Set(Ctx, key, "{}", 0)
	}
}

func (c *PersistentCollection) New(collection string, key string, ttl int) {
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

func (c *PersistentCollection) Get(key string) string{
	return c.Vars[key]
}

func (c *PersistentCollection) SetTtl(key string, ttl int) {
	//TODO
}

func (c *PersistentCollection) Set(key string, value string) {
	c.changed = true
	c.Vars[key] = value
}

func (c *PersistentCollection) Save() {
	if c.changed{
		newcount := "1"
		//TODO real count
		timenow := strconv.FormatInt(time.Now().UnixNano(), 10)
		c.Vars["UPDATE_COUNTER"] = newcount
		c.Vars["LAST_UPDATE_TIME"] = timenow
	}
	js, err := json.Marshal(c.Vars)
	if err != nil{
		fmt.Println("Error serializing collection " + c.key)
	}
	RedisClient.Set(Ctx, c.key, js, 0)
}