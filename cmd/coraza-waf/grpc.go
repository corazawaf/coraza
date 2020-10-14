package main

import (
	"os"
	"net"
	"fmt"
	"sync"
	"time"
	"errors"
	"context"
	"strings"
	"net/url"
	"io/ioutil"
	"path/filepath"	
	"gopkg.in/yaml.v2"
	log "github.com/sirupsen/logrus"
	googlegrpc "google.golang.org/grpc"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"	
	ttlcache "github.com/ReneKroon/ttlcache/v2"
	grpc "github.com/jptosso/coraza-waf/internal/grpc/waf"
)

/*
TODO:
* - Save a copy of the transaction to redis?
*
*/
type grpcAudit struct {
	Files          []string `yaml:"files"`
	Directory      string   `yaml:"directory"`
	Dirmode        int      `yaml:"dirmode"`
	Filemode       int      `yaml:"filemode"`
	RelevantStatus string   `yaml:"relevant_status"`
	LogParts       []string `yaml:"logparts"`
}

type grpcFeatures struct {
	Audit              string `yaml:"audit"`
	Rules              string `yaml:"rules"`
	ContentInjection   string `yaml:"content_injection"`
	RequestBodyAccess  string `yaml:"request_body_access"`
	ResponseBodyAccess string `yaml:"response_body_access"`
	BodyInspection     string `yaml:"body_inspection"`
}

type grpcResponseBody struct {
	InMemoryLimit int64    `yaml:"in_memory_limit"`
	SizeLimit     int64    `yaml:"size_limit"`
	LimitAction   string   `yaml:"limit_action"`
	MimeTypes     []string `yaml:"mime_types"`
}

type grpcRequestBody struct {
	InMemoryLimit int64  `yaml:"in_memory_limit"`
	SizeLimit     int64  `yaml:"size_limit"`
	LimitAction   string `yaml:"limit_action"`
}

type grpcFileUpload struct {
	Path      string `yaml:"path"`
	Limit     int    `yaml:"limit"`
	FileMode  int    `yaml:"filemode"`
	KeepFiles bool   `yaml:"keep_files"`
}

type grpcConfig struct {
	// Specifies which character to use as the separator for
	// application/x-www-form-urlencoded content
	ArgumentSeparator string `yaml:"argument_separator"`

	// Defines the default list of actions, which will be
	// inherited by the rules in the same configuration context.
	DefaultActions string `yaml:"default_actions"`

	// Persistent collection timeout in seconds
	CollectionTimeout int `yaml:"collection_timeout"`

	// File upload configurations
	FileUpload *grpcFileUpload `yaml:"file_upload"`

	// Request Body access configurations
	RequestBody *grpcRequestBody `yaml:"request_body""`

	// Response Body access configurations
	ResponseBody *grpcResponseBody `yaml:"response_body"`

	// Enabled features
	Features *grpcFeatures `yaml:"features"`

	// Audit engine configuration
	Audit *grpcAudit `yaml:"audit"`
}

type grpcConfigFile struct {
	Key     string      `yaml:"key"`

	// Path to profile file
	Profile string      `yaml:"profile"`
	Config  *grpcConfig `yaml:"config"`
}

type grpcMainConfig struct {
	Address          string `yaml:"address"`
	Port             int    `yaml:"port"`
	Pid              string `yaml:"pid"`
	UnixSock         string `yaml:"unix_sock"`
	ApplicationsPath string `yaml:"apps_dir"`
	TxTtl            int    `yaml:"transaction_ttl"`
	MaxConnections   string `yaml:"max_connections"`
	RedisUri         string `yaml:"redis_uri"`
	LogLevel         string `yaml:"loglevel"`

	// Path to GeoIP database
	GeoipDb string `yaml:"geoipdb"`

	// Path to store temporary file
	TmpDir string `yaml:"tmp_dir"`

	// Path to unicode mapping file
	UnicodeMap string `yaml:"unicode_map"`

	// Unicode page for unicode decoding
	// See https://jptosso.github.io/coraza-waf/unicode.html
	UnicodePage             int `yaml:"unicode_page"`
	PcreMatchLimit          int `yaml:"pcre_match_limit"`
	PcreMatchLimitRecursion int `yaml:"pcre_match_limit_recursion"`
}

type grpcServer struct {
	cfg *grpcMainConfig
}

var waflist sync.Map
var transactions *ttlcache.Cache

func initTtl(ttl int) {
	expirationCallback := func(key string, value interface{}) {
		tx := value.(*engine.Transaction)
		tx.ExecutePhase(5)
	}
	transactions = ttlcache.NewCache()
	transactions.SetTTL(time.Duration(time.Duration(ttl) * time.Second))
	transactions.SetExpirationCallback(expirationCallback)
}

func (s *grpcServer) Init(cfgfile string) error {
	data, err := utils.OpenFile(cfgfile)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal([]byte(data), &s.cfg)
	if err != nil {
		return err
	}
	initTtl(s.cfg.TxTtl)
	files := [][]byte{}
	log.Debug("Loading applications from: " + s.cfg.ApplicationsPath)
	filepath.Walk(s.cfg.ApplicationsPath, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".yaml") {
			log.Debug("Loading application: " + path)
			data, _ := ioutil.ReadFile(path)
			files = append(files, data)
		}
		return nil
	})
	for _, data := range files {
		var c *grpcConfigFile
		err = yaml.Unmarshal(data, &c)
		if err != nil {
			return err
		}
		waf := engine.NewWaf()
		parser := &parser.Parser{}
		log.Info("Loading application: " + c.Key)
		parser.Init(waf)
		err := parser.FromFile(c.Profile)
		if err != nil {
			return err
		}
		waflist.Store(c.Key, waf)
	}
	return nil
}

func (s *grpcServer) Serve() error {
	host := s.cfg.Address
	port := s.cfg.Port
	addr := fmt.Sprintf("%s:%d", host, port)
	log.Debug("Going to listen on " + addr)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := googlegrpc.NewServer()
	serviceServer := NewGrpcServer()
	grpc.RegisterTransactionServer(srv, serviceServer)

	if err := srv.Serve(listener); err != nil {
		return err
	}

	return nil
}

func getTransaction(id string) (*engine.Transaction, error) {
	txi, _ := transactions.Get(id)
	if txi == nil {
		return nil, errors.New("Invalid transaction ID")
	}
	return txi.(*engine.Transaction), nil
}

func headersToCollection(headers []*grpc.Header) map[string][]string {
	col := map[string][]string{}
	for _, h := range headers {
		col[h.Key] = h.Values
	}
	return col
}

func collectionToHeaders(collection map[string][]string) []*grpc.Header {
	return nil
}

type grpcHandler struct {
}

func NewGrpcServer() grpc.TransactionServer {
	return &grpcHandler{}
}

func (s grpcHandler) Create(ctx context.Context, req *grpc.NewTransaction) (*grpc.TransactionStatus, error) {
	key := req.Wafkey
	var tx *engine.Transaction
	wi, _ := waflist.Load(key)
	if wi == nil {
		return nil, errors.New("Invalid waf key")
	}
	waf := wi.(*engine.Waf)
	tx = waf.NewTransaction()
	tx.SetRequestHeaders(headersToCollection(req.RequestHeaders))
	uri, _ := url.Parse(req.Uri)
	tx.SetUrl(uri)
	tx.AddGetArgsFromUrl(uri)
	tx.SetRequestLine(req.Method, req.Protocol, req.Uri)
	if req.Evaluate {
		tx.ExecutePhase(1)
	}
	transactions.Set(tx.Id, tx)
	return txToStatus(tx), nil
}

func (s grpcHandler) SetRequestBody(ctx context.Context, req *grpc.NewRequestBody) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil {
		return nil, err
	}
	err = tx.SetRequestBody(req.Body, int64(len(req.Body)), req.Mime)
	if err != nil {
		return nil, err
	}
	if req.Evaluate {
		tx.ExecutePhase(2)
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) SetResponseHeaders(ctx context.Context, req *grpc.NewResponseHeaders) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil {
		return nil, err
	}
	tx.SetResponseStatus(int(req.Status))
	tx.SetResponseHeaders(headersToCollection(req.ResponseHeaders))
	if req.Evaluate {
		tx.ExecutePhase(3)
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) SetResponseBody(ctx context.Context, req *grpc.NewResponseBody) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil {
		return nil, err
	}
	tx.SetResponseBody(req.Body, int64(len(req.Body)))
	if req.Evaluate {
		tx.ExecutePhase(4)
	}
	if req.Finish {
		tx.ExecutePhase(5)
	}
	status := txToStatus(tx)
	//TODO delete tx
	return status, nil
}

func (s grpcHandler) Get(ctx context.Context, req *grpc.TransactionId) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil {
		return nil, err
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) Close(ctx context.Context, req *grpc.TransactionId) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil {
		return nil, err
	}
	tx.ExecutePhase(5)
	transactions.Remove(tx.Id)
	return txToStatus(tx), nil
}

func txToStatus(tx *engine.Transaction) *grpc.TransactionStatus {
	status := &grpc.TransactionStatus{
		Id:        tx.Id,
		Disrupted: tx.Disrupted,
		Status:    int32(tx.Status),
	}
	return status
}
