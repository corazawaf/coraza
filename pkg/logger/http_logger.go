package waf

import(
	"errors"
	"context"
	"bytes"
	"sync"
	"time"
	"net/http"
	"github.com/jptosso/coraza-waf/pkg/engine"
)
type HttpLogger struct{
	working bool
	endpoint string
	mux *sync.RWMutex
	wg sync.WaitGroup
	timeout int

	queue []*models.AuditLog

	LastError error
	UploadCount int64
}

func (hl *HttpLogger) Init(endpoint string){
	hl.endpoint = endpoint
	hl.mux = &sync.RWMutex{}
	hl.working = true
}

func (hl *HttpLogger) Start(){
	//TODO multithreading
	hl.wg.Add(1)
	go func(){
		for hl.working{
			next := hl.next()
			if next == nil{
				time.Sleep(100*time.Millisecond)
				continue
			}else{
				time.Sleep(10*time.Millisecond)
			}
			err := hl.upload(next)
			if err != nil{
				hl.LastError = err
				hl.Add(next)
			}
		}
		defer hl.wg.Done()
	}()
}

func (hl *HttpLogger) next() *models.AuditLog{
	hl.mux.Lock()
	defer hl.mux.Unlock()
	if len(hl.queue) == 0{
		return nil
	}
	hl.UploadCount += 1
	n := hl.queue[0]
	hl.queue = hl.queue[1:]
	return n
}

func (hl *HttpLogger) Stop(){
}

func (hl *HttpLogger) Add(al *models.AuditLog){
	hl.mux.Lock()
	defer hl.mux.Unlock()
	hl.queue = append(hl.queue, al)
}

func (hl *HttpLogger) upload(al *models.AuditLog) error{
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequest("POST", hl.endpoint, bytes.NewBuffer(al.ToJson()))
	
	if err != nil {
	    return err
	}
	req.Header.Set("X-Coraza-Version", "")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil{
		return err
	}

	if resp.StatusCode != 200{
		return errors.New("Invalid response code from server")
	}
	return nil
}