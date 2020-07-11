package utils

import(
	pcre"github.com/gijsbers/go-pcre"
	"sync"
	"strings"
	"fmt"
	"strconv"

)


type LocalCollection struct {
	Data map[string][]string `json:"data"`
	mux *sync.RWMutex
}

func NewCollection() *LocalCollection{
	col := &LocalCollection{}
	col.Init()
	return col
}

func (c *LocalCollection) Init() {
	c.Data = map[string][]string{}
	c.Data[""] = []string{}
	c.mux = &sync.RWMutex{}
}

func (c *LocalCollection) InitCollection(key string) {
	c.Data[key] = []string{}
}

//PCRE compatible collection
func (c *LocalCollection) Get(key string) []string{
	//we return every value in case there is no key but there is a collection
	if len(key) == 0{
		data := []string{}
		// how does modsecurity solves this?
		for k := range c.Data{
			for _, v := range c.Data[k]{
				//val := k + "=" + n
				data = append(data, v)
			}
		}
		return data
	}
	if key[0] == '/'{
		key = TrimLeftChars(key, 1)
		key = strings.TrimSuffix(key, string('/'))
		re := pcre.MustCompile(key, 0)
		result := []string{}
		for k := range c.Data {
		    m := re.Matcher([]byte(k), 0)
		    if m.Matches(){
		    	for _, d := range c.Data[k]{
		    		result = append(result, d)
		    	}
		    }
		}
		return result
	}else{
		return c.Data[key]
	}
}

//PCRE compatible collection
func (c *LocalCollection) GetWithExceptions(key string, exceptions []string) []string{
	//we return every value in case there is no key but there is a collection
	if len(key) == 0{
		data := []string{}
		// how does modsecurity solves this?
		for k := range c.Data{
			if ArrayContains(exceptions, k){
				fmt.Println("Skipping parameter " + k)
				continue
			}
			for _, v := range c.Data[k]{
				//val := k + "=" + n
				data = append(data, v)
			}
		}
		return data
	}

	if key[0] == '/'{
		key = TrimLeftChars(key, 1)
		key = strings.TrimSuffix(key, string('/'))
		re := pcre.MustCompile(key, 0)
		result := []string{}
		for k := range c.Data {
			if ArrayContains(exceptions, k){
				fmt.Println("Skipping parameter " + k)
				continue
			}
		    m := re.Matcher([]byte(k), 0)
		    if m.Matches(){
		    	for _, d := range c.Data[k]{
		    		result = append(result, d)
		    	}
		    }
		}
		return result
	}else{
		ret := []string{}
		//We pass through every record to apply filters
		for k := range c.Data{
			if ArrayContains(exceptions, k){
				fmt.Println("Skipping parameter " + k)
				continue
			}
			if k == key{
				for _, kd := range c.Data[k]{
					ret = append(ret, kd)
				}
			}
		}
		return ret
	}
}

func (c *LocalCollection) GetFirstString() string{
	a := c.Data[""]
	if len(a) > 0{
		return a[0]
	}else{
		return ""
	}
}

func (c *LocalCollection) GetFirstInt64() int64{
	a := c.Data[""]
	if len(a) > 0{
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	}else{
		return 0
	}
}

func (c *LocalCollection) GetFirstInt() int{
	a := c.Data[""]
	if len(a) > 0{
		i, _ := strconv.Atoi(a[0])
		return i
	}else{
		return 0
	}
}

func (c *LocalCollection) Concat() []string{
	r := []string{}
	for k, v := range c.Data{
		r = append(r, fmt.Sprintf("%s=%s", k, v))
	}
	return r
}

func (c *LocalCollection) Add(key string, value []string) {
	c.mux.Lock()
	c.Data[key] = value
	c.mux.Unlock()
}

func (c *LocalCollection) AddToKey(key string, value string) {
	c.mux.Lock()
	c.Data[key] = append(c.Data[key], value)
	c.mux.Unlock()
}


func (c *LocalCollection) Set(key string, value []string) {
	c.Data[key] = value
}

func (c *LocalCollection) AddMap(data map[string][]string) {
	if c == nil{
		fmt.Println("ADSFASDFASDFASDFASDFASDFASDFASDFASDFD CTM C ES NIL")
	}
	for k, v := range data{
		c.mux.RLock()
		c.Data[strings.ToLower(k)] = v
		c.mux.RUnlock()
	}
}

func (c *LocalCollection) Update(key string, value []string) {
	c.Data[key] = value
}

func (c *LocalCollection) Remove(key string) {
	delete(c.Data, key)
}

func (c *LocalCollection) Flush(key string) {
	//not implemented
}

func (c *LocalCollection) GetData() map[string][]string {
	return c.Data
}