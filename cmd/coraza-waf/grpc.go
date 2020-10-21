// Copyright 2020 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	ttlcache "github.com/ReneKroon/ttlcache/v2"
	grpc "github.com/jptosso/coraza-waf/internal/grpc/waf"
	"github.com/jptosso/coraza-waf/pkg/crs"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/parser"
	"github.com/jptosso/coraza-waf/pkg/utils"
	log "github.com/sirupsen/logrus"
	googlegrpc "google.golang.org/grpc"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
	Crs                bool `yaml:"crs"`
	Audit              bool `yaml:"audit"`
	Rules              bool `yaml:"rules"`
	ContentInjection   bool `yaml:"content_injection"`
	RequestBodyAccess  bool `yaml:"request_body_access"`
	ResponseBodyAccess bool `yaml:"response_body_access"`
	BodyInspection     bool `yaml:"body_inspection"`
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

	// OWASP CRS config
	Crs *crs.Crs `yaml:"crs"`
}

type grpcConfigFile struct {
	Key string `yaml:"key"`

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
	srv *googlegrpc.Server
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
	switch s.cfg.LogLevel {
	case "info":
		log.SetLevel(log.InfoLevel)
		break
	case "debug":
		log.SetLevel(log.DebugLevel)
		break
	case "warn":
		log.SetLevel(log.WarnLevel)
		break
	case "error":
		log.SetLevel(log.ErrorLevel)
		break
	default:
		log.SetLevel(log.WarnLevel)
		break
	}
	initTtl(s.cfg.TxTtl)
	files := []string{}
	log.Debug("Loading applications from: " + s.cfg.ApplicationsPath)
	filepath.Walk(s.cfg.ApplicationsPath, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".yaml") {
			log.Debug("Loading application: " + path)
			files = append(files, path)
		}
		return nil
	})
	for _, path := range files {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		var c *grpcConfigFile
		err = yaml.Unmarshal(data, &c)
		if err != nil {
			return err
		}
		waf := engine.NewWaf()
		parser := &parser.Parser{}
		log.Info("Loading application: " + c.Key)
		parser.Init(waf)
		err = parser.FromFile(c.Profile)
		if err != nil {
			return err
		}
		if c.Config.Features.Crs {
			log.Info("Application is using OWASP CRS")
			err = c.Config.Crs.Init(waf)
			if err != nil {
				return err
			}
			err := c.Config.Crs.Build()
			if err != nil {
				return err
			}
			log.Debug(fmt.Sprintf("%d rules after CRS", waf.Rules.Count()))
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

	s.srv = googlegrpc.NewServer()
	serviceServer := NewGrpcServer()
	grpc.RegisterTransactionServer(s.srv, serviceServer)

	if err := s.srv.Serve(listener); err != nil {
		return err
	}

	return nil
}

func (s *grpcServer) Close() {
	log.Info("Attempting to gracefully stop GRPC")
	s.srv.GracefulStop()
	log.Info(fmt.Sprintf("GRPC stopped, attempting to close %d transactions, it might take a few minutes", transactions.Count()))
	transactions.Close()
	for transactions.Count() > 0 {
		//Waiting for all transactions to be closed
	}
	log.Warn("We just deleted all pending transactions, it might be fixed in the future.")
	log.Info("All transactions closed")
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
	log.Debug("Created transaction " + tx.Id)
	tx.SetRequestHeaders(headersToCollection(req.RequestHeaders))
	uri, _ := url.Parse(req.Uri)
	tx.SetUrl(uri)
	tx.AddGetArgsFromUrl(uri)
	tx.SetRequestLine(req.Method, req.Protocol, req.Uri)
	tx.SetRemoteAddress(req.RequestAddr, int(req.RequestPort))

	if req.Evaluate {
		log.Debug("Evaluating transaction " + tx.Id)
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
	tx.ExecutePhase(5)
	status := txToStatus(tx)
	transactions.Remove(tx.Id)
	return status, err
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

func (s grpcHandler) GetCollection(ctx context.Context, req *grpc.CollectionRequest) (*grpc.CollectionResponse, error) {
	wi, _ := waflist.Load(req.Wafkey)
	if wi == nil {
		return nil, errors.New("Invalid Waf Key")
	}
	waf := wi.(*engine.Waf)
	cols := []*grpc.Collection{}
	cdata := waf.PersistenceEngine.Get(fmt.Sprintf("c-%s-%s-%s", waf.WebAppId, req.Name, req.Key))
	for k, v := range cdata {
		cols = append(cols, &grpc.Collection{
			Key:    k,
			Values: v,
		})
	}
	col := &grpc.CollectionResponse{
		Name:        fmt.Sprintf("%s:%s", req.Name, req.Key),
		Collections: cols,
	}
	return col, nil
}

func txToStatus(tx *engine.Transaction) *grpc.TransactionStatus {
	status := &grpc.TransactionStatus{
		Id:        tx.Id,
		Disrupted: tx.Disrupted,
		Status:    int32(tx.Status),
	}
	return status
}
