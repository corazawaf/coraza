package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	grpc "github.com/jptosso/coraza-waf/internal/grpc/waf"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"github.com/jptosso/coraza-waf/pkg/utils"
	googlegrpc "google.golang.org/grpc"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/url"
	"path/filepath"
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
	ArgumentSeparator       string            `yaml:"argument_separator"`
	DefaultActions          string            `yaml:"default_actions"`
	GeoipDb                 string            `yaml:"geoipdb"`
	TmpDir                  string            `yaml:"tmp_dir"`
	UnicodeMap              string            `yaml:"unicode_map"`
	UnicodePage             int               `yaml:"unicode_page"`
	CollectionTimeout       int               `yaml:"collection_timeout"`
	PcreMatchLimit          int               `yaml:"pcre_match_limit"`
	PcreMatchLimitRecursion int               `yaml:"pcre_match_limit_recursion"`
	FileUpload              *grpcFileUpload   `yaml:"file_upload"`
	RequestBody             *grpcRequestBody  `yaml:request_body"`
	ResponseBody            *grpcResponseBody `yaml:"response_body"`
	Features                *grpcFeatures     `yaml:"features"`
	Audit                   *grpcAudit        `yaml:"audit"`
}

type grpcConfigFile struct {
	Key     string      `yaml:"key"`
	Profile string      `yaml:"profile"`
	Config  *grpcConfig `yaml:"config"`
}

type grpcMainConfig struct {
	Address          string `yaml:"address"`
	Port             string `yaml:"port"`
	Pid              string `yaml:"pid"`
	UnixSock         string `yaml:"unix_sock"`
	ApplicationsPath string `yaml:"apps_dir"`
	TxMaxTtl         string `yaml:"transaction_max_ttl"`
	MaxConnections   string `yaml:"max_connections"`
	RedisUri         string `yaml:"redis_uri"`
}

type grpcServer struct {
	cfg *grpcMainConfig
}

var waflist sync.Map
var transactions sync.Map

func (s *grpcServer) Init(cfgfile string) error {
	data, err := utils.OpenFile(cfgfile)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal([]byte(data), &s.cfg)
	if err != nil {
		return err
	}
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
	host := "127.0.0.1"
	port := 5001
	addr := fmt.Sprintf("%s:%d", host, port)
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

func getTransaction(id string) (*engine.Transaction, error){
	txi, _ := transactions.Load(id)
	if txi == nil {
		return nil, errors.New("Invalid transaction ID");
	}
	return txi.(*engine.Transaction), nil
}

func headersToCollection(headers []*grpc.Header) map[string][]string {
	col := map[string][]string{}
	for _, h := range headers{
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
	if req.Evaluate{
		tx.ExecutePhase(1)
	}
	transactions.Store(tx.Id, tx)
	return txToStatus(tx), nil
}

func (s grpcHandler) SetRequestBody(ctx context.Context, req *grpc.NewRequestBody) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil{
		return nil, err
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) SetResponseHeaders(ctx context.Context, req *grpc.NewResponseHeaders) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil{
		return nil, err
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) SetResponseBody(ctx context.Context, req *grpc.NewResponseBody) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil{
		return nil, err
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) AddRequestFiles(ctx context.Context, req *grpc.RequestFiles) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil{
		return nil, err
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) Get(ctx context.Context, req *grpc.TransactionId) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil{
		return nil, err
	}
	return txToStatus(tx), nil
}

func (s grpcHandler) Close(ctx context.Context, req *grpc.TransactionId) (*grpc.TransactionStatus, error) {
	tx, err := getTransaction(req.Txid)
	if err != nil{
		return nil, err
	}
	return txToStatus(tx), nil
}

func txToStatus(tx *engine.Transaction) *grpc.TransactionStatus {
	status := &grpc.TransactionStatus{
		Id: tx.Id,
		Disrupted: tx.Disrupted,
		Status: int32(tx.Status),
	}
	return status
}
