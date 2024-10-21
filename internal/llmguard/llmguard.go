package llmguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Scanner string

var (
	Anonymize          Scanner = "Anonymize"
	BanCode            Scanner = "Bancode"
	BanCompetitors     Scanner = "BanCompetitors"
	BanSubstrings      Scanner = "BanSubstrings"
	BanTopics          Scanner = "BanTopics"
	Code               Scanner = "Code"
	Gibberish          Scanner = "Gibberish"
	InvisibleText      Scanner = "InvisibleText"
	Language           Scanner = "Language"
	PromptInjection    Scanner = "PromptInjection"
	Regex              Scanner = "Regex"
	Secrets            Scanner = "Secrets"
	Sentiment          Scanner = "Sentiment"
	TokenLimit         Scanner = "TokenLimit"
	Toxicity           Scanner = "Toxicity"
	Bias               Scanner = "Bias"
	Deanonymize        Scanner = "Deanonymize"
	FactualConsistency Scanner = "FactualConsistency"
	JSON               Scanner = "JSON"
	LanguageSame       Scanner = "LanguageSame"
	MaliciousURLs      Scanner = "MaliciousURLs"
	NoRefusal          Scanner = "NoRefusal"
	ReadingTime        Scanner = "ReadingTime"
	Relevance          Scanner = "Relevance"
	Sensitive          Scanner = "Sensitive"
)

type ScannersResult struct {
	Anonymize          float32 `json:"Anonymize,omitempty"`
	BanCode            float32 `json:"BanCode,omitempty"`
	BanCompetitors     float32 `json:"BanCompetitors,omitempty"`
	BanSubstrings      float32 `json:"BanSubstrings,omitempty"`
	BanTopics          float32 `json:"BanTopics,omitempty"`
	Code               float32 `json:"Code,omitempty"`
	Gibberish          float32 `json:"Gibberish,omitempty"`
	InvisibleText      float32 `json:"InvisibleText,omitempty"`
	Language           float32 `json:"Language,omitempty"`
	PromptInjection    float32 `json:"PromptInjection,omitempty"`
	Regex              float32 `json:"Regex,omitempty"`
	Secrets            float32 `json:"Secrets,omitempty"`
	Sentiment          float32 `json:"Sentiment,omitempty"`
	TokenLimit         float32 `json:"TokenLimit,omitempty"`
	Toxicity           float32 `json:"Toxicity,omitempty"`
	Bias               float32 `json:"Bias,omitempty"`
	Deanonymize        float32 `json:"Deanonymize,omitempty"`
	FactualConsistency float32 `json:"FactualConsistency,omitempty"`
	JSON               float32 `json:"JSON,omitempty"`
	LanguageSame       float32 `json:"LanguageSame,omitempty"`
	MaliciousURLs      float32 `json:"MaliciousURLs,omitempty"`
	NoRefusal          float32 `json:"NoRefusal,omitempty"`
	ReadingTime        float32 `json:"ReadingTime,omitempty"`
	Relevance          float32 `json:"Relevance,omitempty"`
	Sensitive          float32 `json:"Sensitive,omitempty"`
}

type LLMGuardRequest interface {
	RemoveScanner(Scanner)
	AddScannerSuppress(Scanner)
}

type LLMGuardResponse struct {
	IsValid         bool           `json:"is_valid"`
	Scanners        ScannersResult `json:"scanners"`
	SanitizedPrompt string         `json:"sanitized_prompt,omitempty"`
}

func (l *LLMGuardResponse) Valid() bool {
	return l.IsValid
}

type LLMGuardPromptRequest struct {
	Prompt            string
	Scanners_Suppress []Scanner
}

func (lpr *LLMGuardPromptRequest) AddScannerSuppress(scanner Scanner) {
	lpr.Scanners_Suppress = append(lpr.Scanners_Suppress, scanner)
}

func (lpr *LLMGuardPromptRequest) RemoveScanner(scanner Scanner) {
	if len(lpr.Scanners_Suppress) == 0 {
		return
	}
	for i, sc := range lpr.Scanners_Suppress {
		if sc == scanner {
			lpr.Scanners_Suppress = append(lpr.Scanners_Suppress[:i], lpr.Scanners_Suppress[i+1:]...)
		}
	}
}

func (lpr *LLMGuardPromptRequest) RemoveFromScannerList(scanner Scanner) {
	lpr.Scanners_Suppress = RemoveFromScannerList(scanner)
}

//TODO NewLLMGuardPromptRequest function

type LLMGuardOutputRequest struct {
	Prompt            string
	Output            string
	Scanners_Suppress []Scanner
}

func (lor *LLMGuardOutputRequest) AddScannerSuppress(scanner Scanner) {
	lor.Scanners_Suppress = append(lor.Scanners_Suppress, scanner)
}

func (lor *LLMGuardOutputRequest) RemoveFromScannerList(scanner Scanner) {
	lor.Scanners_Suppress = RemoveFromScannerList(scanner)
}

func LLMguardScanWithTransport(url string, data LLMGuardRequest) (*LLMGuardResponse, error) {
	byteData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshling request error: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(byteData))
	if err != nil {
		return nil, fmt.Errorf("new request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := LlmGuardClient.clientPool.Get().(*http.Client)
	defer LlmGuardClient.clientPool.Put(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get response from api error: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get response status error: %s, status code is %d", resp.Status, resp.StatusCode)
	}

	var llmguardResponse LLMGuardResponse
	byteResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body error: %w", err)
	}

	err = json.Unmarshal(byteResp, &llmguardResponse)
	if err != nil {
		return nil, fmt.Errorf("unmarshling response body error: %w", err)
	}
	return &llmguardResponse, nil
}

var Scanner_List = []Scanner{
	Anonymize,
	BanCode,
	BanCompetitors,
	BanSubstrings,
	BanTopics,
	Code,
	Gibberish,
	InvisibleText,
	Language,
	PromptInjection,
	Regex,
	Secrets,
	Sentiment,
	TokenLimit,
	Toxicity,
	Bias,
	Deanonymize,
	FactualConsistency,
	JSON,
	LanguageSame,
	MaliciousURLs,
	NoRefusal,
	ReadingTime,
	Relevance,
	Sensitive,
}

func RemoveFromScannerList(s Scanner) []Scanner {
	var new_scanner_list []Scanner
	for _, v := range Scanner_List {
		if v != s {
			new_scanner_list = append(new_scanner_list, v)
		}
	}
	return new_scanner_list
}

const (
	REQAPIPATH = "/scan/prompt"
	RESAPIPATH = "/scan/output"
)

// 对外提供大模型检测调用接口
func DetectQuestion(reqBody string) (bool, ScannersResult) {
	//基于请求体内容提取问题
	question, ok := ContentExtractFromJSONDATA(reqBody, REQUESTBODY)
	if !ok {
		return false, ScannersResult{}
	}
	//调用接口地址url
	url := LlmGuardClient.config.Address + REQAPIPATH
	//调用接口返回结果
	promptRequest := &LLMGuardPromptRequest{
		Prompt: question,
	}
	//提取结果，判定黑白，如果是黑就返回true，是白就返回false，如果是黑，需要返回命中了什么检测
	res, err := LLMguardScanWithTransport(url, promptRequest)
	if err != nil {
		return false, ScannersResult{}
	}
	if !res.Valid() {
		return true, res.Scanners
	}
	return false, res.Scanners
}
