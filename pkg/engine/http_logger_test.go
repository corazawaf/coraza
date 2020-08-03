package engine

import(
	_"testing"
	_"time"
	_"fmt"
)
/*
func TestHttpLogger(t *testing.T) {
	logger := &HttpLogger{}
	logger.Init("https://postman-echo.com/post")
	logger.Start()
	defer logger.Stop()
	tx := &Transaction{}
	w := &Waf{}
	w.Init()
	tx.Init(w)
	tx.InitTxCollection()
	al := &models.AuditLog{}
	al.Parse(&tx.Transaction)
	logger.Add(al)
	counter := 0
	for logger.UploadCount == 0{
		time.Sleep(100 * time.Millisecond)
		counter += 1
		if counter >= 300{
			break
		}
	}

	if logger.LastError != nil || logger.UploadCount == 0{
		t.Errorf("Failed to upload https log")
	}

	logger.Init("https://postman-echo.com/get")
	logger.Add(al)

	for logger.UploadCount < 2{
		time.Sleep(100 * time.Millisecond)
		counter += 1
		fmt.Println(counter)
		if counter >= 300{
			break
		}
	}	
	if logger.LastError == nil{
		t.Errorf("False negative while uploading logs")
	}
}*/