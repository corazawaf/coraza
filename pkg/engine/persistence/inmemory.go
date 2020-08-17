package persistence

type MemoryEngine struct{
	data map[string]map[string][]string
}

func (r *MemoryEngine) Init(url string) error{
	r.data = map[string]map[string][]string{}
	return nil
}

func (r *MemoryEngine) Get(key string) map[string][]string{
	return r.data[key]
}

func (r *MemoryEngine) Set(key string, data map[string][]string) error{
	r.data[key] = data
	return nil
}