package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blackestwhite/masterdns-qs-tunnel/internal/base32x"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		parsed, err := time.ParseDuration(asString)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}

	var asNumber float64
	if err := json.Unmarshal(data, &asNumber); err == nil {
		*d = Duration(time.Duration(asNumber * float64(time.Second)))
		return nil
	}
	return fmt.Errorf("duration must be a string or number")
}

func (d Duration) Value() time.Duration {
	return time.Duration(d)
}

type ClientConfig struct {
	RelayListen         string   `json:"relay_listen"`
	DownlinkBind        string   `json:"downlink_bind"`
	AnnouncePublicIP    string   `json:"announce_public_ip"`
	AnnounceReceivePort int      `json:"announce_receive_port"`
	SpoofSourceIP       string   `json:"spoof_source_ip"`
	SpoofSourcePort     int      `json:"spoof_source_port"`
	InfoSecret          string   `json:"info_secret"`
	SendDomains         []string `json:"send_domains"`
	Resolvers           []string `json:"resolvers"`
	ResolversFile       string   `json:"resolvers_file"`
	ClientID            string   `json:"client_id"`
	ClientIDLength      int      `json:"client_id_length"`
	OffsetWidth         int      `json:"offset_width"`
	MaxLabelLen         int      `json:"max_label_len"`
	MaxQNameLen         int      `json:"max_qname_len"`
	QueryType           uint16   `json:"query_type"`
	Duplication         int      `json:"duplication"`
	SendDelay           Duration `json:"send_delay"`
	InfoInterval        Duration `json:"info_interval"`
}

type ServerConfig struct {
	Listen            string   `json:"listen"`
	AllowedDomains    []string `json:"allowed_domains"`
	Upstream          string   `json:"upstream"`
	ClientIDLength    int      `json:"client_id_length"`
	OffsetWidth       int      `json:"offset_width"`
	InfoSecret        string   `json:"info_secret"`
	ReassemblyTimeout Duration `json:"reassembly_timeout"`
	SessionIdle       Duration `json:"session_idle_timeout"`
	UseRawSpoofing    bool     `json:"use_raw_spoofing"`
	ReplyTTL          int      `json:"reply_ttl"`
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		RelayListen:         "127.0.0.1:18080",
		DownlinkBind:        "0.0.0.0:0",
		ClientIDLength:      7,
		OffsetWidth:         3,
		MaxLabelLen:         63,
		MaxQNameLen:         253,
		QueryType:           1,
		Duplication:         1,
		SendDelay:           Duration(2 * time.Millisecond),
		InfoInterval:        Duration(20 * time.Second),
		AnnounceReceivePort: 0,
	}
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Listen:            ":5300",
		ClientIDLength:    7,
		OffsetWidth:       3,
		ReassemblyTimeout: Duration(30 * time.Second),
		SessionIdle:       Duration(2 * time.Minute),
		ReplyTTL:          64,
	}
}

func LoadClient(path string) (ClientConfig, error) {
	cfg := DefaultClientConfig()
	if err := loadJSON(path, &cfg); err != nil {
		return ClientConfig{}, err
	}
	return cfg, cfg.Validate()
}

func LoadServer(path string) (ServerConfig, error) {
	cfg := DefaultServerConfig()
	if err := loadJSON(path, &cfg); err != nil {
		return ServerConfig{}, err
	}
	return cfg, cfg.Validate()
}

func loadJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (c *ClientConfig) EnsureClientID() error {
	if c.ClientIDLength <= 0 {
		return fmt.Errorf("client_id_length must be positive")
	}
	if c.ClientID == "" {
		buf := make([]byte, c.ClientIDLength)
		seed := make([]byte, c.ClientIDLength)
		if _, err := rand.Read(seed); err != nil {
			return err
		}
		for i := range buf {
			buf[i] = "abcdefghijklmnopqrstuvwxyz234567"[int(seed[i])%32]
		}
		c.ClientID = string(buf)
		return nil
	}
	c.ClientID = strings.ToLower(strings.TrimSpace(c.ClientID))
	if len(c.ClientID) != c.ClientIDLength {
		return fmt.Errorf("client_id must be exactly %d chars", c.ClientIDLength)
	}
	if _, err := base32x.Base32ToNumber([]byte(c.ClientID)); err != nil {
		return fmt.Errorf("client_id must be lower base32: %w", err)
	}
	return nil
}

func (c ClientConfig) Validate() error {
	if len(c.SendDomains) == 0 {
		return fmt.Errorf("send_domains is required")
	}
	if strings.TrimSpace(c.AnnouncePublicIP) == "" {
		return fmt.Errorf("announce_public_ip is required")
	}
	if strings.TrimSpace(c.SpoofSourceIP) == "" {
		return fmt.Errorf("spoof_source_ip is required")
	}
	if c.SpoofSourcePort < 1 || c.SpoofSourcePort > 65535 {
		return fmt.Errorf("spoof_source_port must be 1..65535")
	}
	if c.ClientIDLength <= 0 {
		return fmt.Errorf("client_id_length must be positive")
	}
	if c.OffsetWidth <= 0 {
		return fmt.Errorf("offset_width must be positive")
	}
	if c.MaxLabelLen <= 0 || c.MaxLabelLen > 63 {
		return fmt.Errorf("max_label_len must be 1..63")
	}
	if c.MaxQNameLen < 64 {
		return fmt.Errorf("max_qname_len must be at least 64")
	}
	if c.QueryType == 0 {
		return fmt.Errorf("query_type must be non-zero")
	}
	if c.Duplication <= 0 {
		return fmt.Errorf("duplication must be positive")
	}
	if len(c.Resolvers) == 0 && strings.TrimSpace(c.ResolversFile) == "" {
		return fmt.Errorf("either resolvers or resolvers_file is required")
	}
	return nil
}

func (c ServerConfig) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return fmt.Errorf("listen is required")
	}
	if strings.TrimSpace(c.Upstream) == "" {
		return fmt.Errorf("upstream is required")
	}
	if len(c.AllowedDomains) == 0 {
		return fmt.Errorf("allowed_domains is required")
	}
	if c.ClientIDLength <= 0 {
		return fmt.Errorf("client_id_length must be positive")
	}
	if c.OffsetWidth <= 0 {
		return fmt.Errorf("offset_width must be positive")
	}
	if c.ReplyTTL <= 0 || c.ReplyTTL > 255 {
		return fmt.Errorf("reply_ttl must be 1..255")
	}
	return nil
}
