package engine

type Crs struct {
	DefaultParanoia              int
	EnforceUrlEncoded            bool
	InboundAnomalyScoreThreshold int
	OutboundScoreThreshold       int
	Exclusions                   map[string][]string // Path and application
	AllowedHttpMethods           []string
	AllowedReqContentType        []string
	AllowedHttpVersions          []string
	AllowedReqCharset            []string
	ForbiddenFileExtensions      []string
	ForbiddenRequestHeaders      []string
	StaticFileExtensions         []string
	CountryBlock                 []string
	MaxNumArgs                   int
	MaxArgNameLength             int
	MaxArgValueLength            int
	MaxFileSize                  int64
	MaxCombinedFileSize          int64
	SamplingPercentaje           int
	BlockBlSearchIp              bool
	BlockBlSuspiciousIp          bool
	BlockBlHarvesterIp           bool
	BlockBlSpammerIp             bool

	DosBlockTimeout         int
	DosCounterThreshold     int
	DosBurstTimeSlice       int
	ValidateUtf8Encoding    bool
	ReputationBlock         bool
	ReputationBlockDuration int

	IpKey      string
	SessionKey string
}

func (c *Crs) BuildRules() (string, error) {
	return "", nil
}

func NewCrs() *Crs {
	return &Crs{
		DefaultParanoia:    1,
		AllowedHttpMethods: []string{"GET", "HEAD", "POST", "OPTIONS"},
	}
}
