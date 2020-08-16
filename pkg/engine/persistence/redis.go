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

func (r *RedisEngine) Init() error{
	r.ctx = context.Background()
	return nil
}

func (r *RedisEngine) Get(key string) map[string][]string{
	return map[string][]string{}
}

func (r *RedisEngine) Set(key string, data map[string][]string) error{
	js, err := json.Marshal(data)
	if err != nil{
		return err
	}
	r.rc.Set(r.ctx, key, js, 0)
	return nil
}