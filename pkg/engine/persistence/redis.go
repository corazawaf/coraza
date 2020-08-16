package persistence
import(
	"context"
	"encoding/json"
    "github.com/go-redis/redis/v8"
)

type RedisEngine struct{
	rc *redis.Client
	ctx context.Context
}

func (r *RedisEngine) Init(url string) error{
	r.ctx = context.Background()
	return nil
}

func (r *RedisEngine) Get(key string) map[string][]string{
	var res map[string][]string
	val, err := r.rc.Get(r.ctx, key).Result()
	if err != nil {
		return nil
	}
	err = json.Unmarshal([]byte(val), &res)
	if err != nil {
		return nil
	}
	return res
}

func (r *RedisEngine) Set(key string, data map[string][]string) error{
	js, err := json.Marshal(data)
	if err != nil{
		return err
	}
	r.rc.Set(r.ctx, key, js, 0)
	return nil
}