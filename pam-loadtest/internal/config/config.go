package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Protocol string

type ExecutionMode string

const (
	SSH     Protocol      = "ssh"
	RDP     Protocol      = "rdp"
	VNC     Protocol      = "vnc"
	Web     Protocol      = "web"
	MySQL   Protocol      = "mysql"
	Direct  ExecutionMode = "direct"
	Browser ExecutionMode = "browser"
)

var protocolOrder = []Protocol{SSH, RDP, VNC, Web, MySQL}

type PAM struct {
	BaseURL     string `yaml:"base_url"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
}

type Config struct {
	Name                          string                     `yaml:"name"`
	Total                         int                        `yaml:"total"`
	Ramp                          time.Duration              `yaml:"-"`
	Hold                          time.Duration              `yaml:"-"`
	SSHActivityInterval           time.Duration              `yaml:"-"`
	SSHActivityMode               string                     `yaml:"ssh_activity_mode"`
	GraphicalActivityIntervals    map[Protocol]time.Duration `yaml:"-"`
	RampText                      string                     `yaml:"ramp"`
	HoldText                      string                     `yaml:"hold"`
	SSHActivityIntervalText       string                     `yaml:"ssh_activity_interval"`
	GraphicalActivityIntervalText map[Protocol]string        `yaml:"graphical_activity_intervals"`
	ContinueOnErrors              bool                       `yaml:"continue_on_errors"`
	ConnectionOnly                bool                       `yaml:"connection_only"`
	ConnectRetries                int                        `yaml:"connect_retries"`
	Seed                          int64                      `yaml:"seed"`
	Protocols                     map[Protocol]int           `yaml:"protocols"`
	ExecutionModes                map[Protocol]ModeCounts    `yaml:"execution_modes"`
	PAM                           PAM                        `yaml:"pam"`
	Assets                        map[Protocol]Asset         `yaml:"assets"`
}

type ModeCounts struct {
	Direct  int `yaml:"direct"`
	Browser int `yaml:"browser"`
}

type Asset struct {
	AssetIDEnv     string `yaml:"asset_id_env"`
	AccountIDEnv   string `yaml:"account_id_env"`
	URLTemplateEnv string `yaml:"url_template_env"`
}

type Job struct {
	ID        int
	Protocol  Protocol
	Mode      ExecutionMode
	AssetID   string
	AccountID string
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if c.PAM.Username != "" || c.PAM.Password != "" {
		return Config{}, fmt.Errorf("inline PAM credentials are forbidden")
	}
	if c.PAM.UsernameEnv == "" || c.PAM.PasswordEnv == "" {
		return Config{}, fmt.Errorf("PAM credential environment names are required")
	}
	if strings.ContainsAny(c.PAM.UsernameEnv+c.PAM.PasswordEnv, "=\r\n") {
		return Config{}, fmt.Errorf("invalid credential environment name")
	}
	if u, err := url.ParseRequestURI(c.PAM.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return Config{}, fmt.Errorf("invalid PAM base URL")
	}
	c.Ramp, err = time.ParseDuration(c.RampText)
	if err != nil || c.Ramp <= 0 {
		return Config{}, fmt.Errorf("invalid ramp duration")
	}
	c.Hold, err = time.ParseDuration(c.HoldText)
	if err != nil || c.Hold <= 0 {
		return Config{}, fmt.Errorf("invalid hold duration")
	}
	c.SSHActivityInterval = time.Second
	if c.SSHActivityIntervalText != "" {
		c.SSHActivityInterval, err = time.ParseDuration(c.SSHActivityIntervalText)
		if err != nil || c.SSHActivityInterval < time.Second || c.SSHActivityInterval > time.Minute || c.SSHActivityInterval%time.Second != 0 {
			return Config{}, fmt.Errorf("invalid SSH activity interval")
		}
	}
	if c.SSHActivityMode == "" {
		c.SSHActivityMode = "output"
	}
	if c.SSHActivityMode != "output" && c.SSHActivityMode != "keepalive" {
		return Config{}, fmt.Errorf("invalid SSH activity mode")
	}
	c.GraphicalActivityIntervals = make(map[Protocol]time.Duration)
	for protocol, text := range c.GraphicalActivityIntervalText {
		if protocol != RDP && protocol != VNC && protocol != Web && protocol != MySQL {
			return Config{}, fmt.Errorf("invalid graphical activity protocol %s", protocol)
		}
		interval, parseErr := time.ParseDuration(text)
		if parseErr != nil || interval < time.Second || interval > time.Minute || interval%time.Second != 0 {
			return Config{}, fmt.Errorf("invalid graphical activity interval for %s", protocol)
		}
		c.GraphicalActivityIntervals[protocol] = interval
	}
	if c.Seed == 0 {
		c.Seed = 1
	}
	if c.ConnectRetries < 0 || c.ConnectRetries > 3 {
		return Config{}, fmt.Errorf("connect retries must be between 0 and 3")
	}
	return c, nil
}

func (c Config) ActivityInterval(protocol Protocol) time.Duration {
	if protocol == SSH && c.SSHActivityInterval > 0 {
		return c.SSHActivityInterval
	}
	if interval := c.GraphicalActivityIntervals[protocol]; interval > 0 {
		return interval
	}
	return time.Second
}

func (c Config) Credentials() (string, string, error) {
	u, uok := os.LookupEnv(c.PAM.UsernameEnv)
	p, pok := os.LookupEnv(c.PAM.PasswordEnv)
	if !uok || !pok || u == "" || p == "" {
		return "", "", fmt.Errorf("required PAM credential environment variables are not set")
	}
	return u, p, nil
}

func (c Config) Asset(protocol Protocol) (assetID, accountID, urlTemplate string, err error) {
	a, ok := c.Assets[protocol]
	if !ok {
		return "", "", "", fmt.Errorf("asset mapping for %s is missing", protocol)
	}
	if a.AssetIDEnv == "" || a.AccountIDEnv == "" {
		return "", "", "", fmt.Errorf("asset environment names for %s are required", protocol)
	}
	assetID = os.Getenv(a.AssetIDEnv)
	accountID = os.Getenv(a.AccountIDEnv)
	if assetID == "" || accountID == "" {
		return "", "", "", fmt.Errorf("asset environment values for %s are not set", protocol)
	}
	if a.URLTemplateEnv != "" {
		urlTemplate = os.Getenv(a.URLTemplateEnv)
	}
	return
}

func (c Config) Expand() ([]Job, error) {
	if c.Total <= 0 {
		return nil, fmt.Errorf("total must be positive")
	}
	sum := 0
	for protocol, count := range c.Protocols {
		if count < 0 {
			return nil, fmt.Errorf("negative count for %s", protocol)
		}
		known := false
		for _, p := range protocolOrder {
			if protocol == p {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown protocol %q", protocol)
		}
		sum += count
	}
	if sum != c.Total {
		return nil, fmt.Errorf("protocol total %d does not match total %d", sum, c.Total)
	}
	jobs := make([]Job, 0, c.Total)
	for _, protocol := range protocolOrder {
		count := c.Protocols[protocol]
		if count == 0 {
			continue
		}
		modes, explicit := c.ExecutionModes[protocol]
		if explicit {
			if modes.Direct < 0 || modes.Browser < 0 {
				return nil, fmt.Errorf("negative execution mode count for %s", protocol)
			}
			if modes.Direct+modes.Browser != count {
				return nil, fmt.Errorf("execution mode total %d for %s does not match protocol count %d", modes.Direct+modes.Browser, protocol, count)
			}
		} else if protocol == SSH || protocol == MySQL {
			modes.Direct = count
		} else {
			modes.Browser = count
		}
		for i := 0; i < modes.Browser; i++ {
			jobs = append(jobs, Job{ID: len(jobs) + 1, Protocol: protocol, Mode: Browser})
		}
		for i := 0; i < modes.Direct; i++ {
			jobs = append(jobs, Job{ID: len(jobs) + 1, Protocol: protocol, Mode: Direct})
		}
	}
	return jobs, nil
}
