package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	maxThreads         = 25000
	highThreadWarning  = 20000
	defaultConfigPath  = "config.json"
	defaultResultsPath = "results.csv"
)

type rawConfig struct {
	Host              string `json:"host"`
	Threads           int    `json:"threads"`
	Duration          string `json:"duration"`
	TargetTPS         int    `json:"target_tps"`
	RampUp            string `json:"ramp_up"`
	ConnectTimeout    string `json:"connect_timeout"`
	WriteTimeout      string `json:"write_timeout"`
	HeartbeatInterval string `json:"heartbeat_interval"`
	StatsInterval     string `json:"stats_interval"`
	ResultsFile       string `json:"results_file"`
	AppName           string `json:"app_name"`
	ServerID          int    `json:"server_id"`
	UsernamePrefix    string `json:"username_prefix"`
	SessionPrefix     string `json:"session_prefix"`
	ClientIP          string `json:"client_ip"`
	ServerAddress     string `json:"server_address"`
	RequestMethod     string `json:"request_method"`
	RequestPath       string `json:"request_path"`
	RequestHost       string `json:"request_host"`
	ResponseStatus    int    `json:"response_status"`
	ResponseBody      string `json:"response_body"`
	ResponseBodySize  int    `json:"response_body_size"`
	ResponseChunkSize int    `json:"response_chunk_size"`
}

type Config struct {
	Host              string
	Threads           int
	Duration          time.Duration
	TargetTPS         int
	RampUp            time.Duration
	ConnectTimeout    time.Duration
	WriteTimeout      time.Duration
	HeartbeatInterval time.Duration
	StatsInterval     time.Duration
	ResultsFile       string
	AppName           string
	ServerID          int
	UsernamePrefix    string
	SessionPrefix     string
	ClientIP          string
	ServerAddress     string
	RequestMethod     string
	RequestPath       string
	RequestHost       string
	ResponseStatus    int
	ResponseBody      string
	ResponseBodySize  int
	ResponseChunkSize int
}

func LoadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config %q: %w", path, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var raw rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	duration, err := positiveDuration("duration", raw.Duration)
	if err != nil {
		return Config{}, err
	}
	rampUp, err := nonNegativeDuration("ramp_up", raw.RampUp)
	if err != nil {
		return Config{}, err
	}
	connectTimeout, err := positiveDuration("connect_timeout", raw.ConnectTimeout)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := positiveDuration("write_timeout", raw.WriteTimeout)
	if err != nil {
		return Config{}, err
	}
	heartbeatInterval, err := positiveDuration("heartbeat_interval", raw.HeartbeatInterval)
	if err != nil {
		return Config{}, err
	}
	statsInterval, err := positiveDuration("stats_interval", raw.StatsInterval)
	if err != nil {
		return Config{}, err
	}

	config := Config{
		Host: strings.TrimSpace(raw.Host), Threads: raw.Threads,
		Duration: duration, TargetTPS: raw.TargetTPS, RampUp: rampUp,
		ConnectTimeout: connectTimeout, WriteTimeout: writeTimeout,
		HeartbeatInterval: heartbeatInterval, StatsInterval: statsInterval,
		ResultsFile: strings.TrimSpace(raw.ResultsFile), AppName: strings.TrimSpace(raw.AppName),
		ServerID: raw.ServerID, UsernamePrefix: raw.UsernamePrefix, SessionPrefix: raw.SessionPrefix,
		ClientIP: strings.TrimSpace(raw.ClientIP), ServerAddress: strings.TrimSpace(raw.ServerAddress),
		RequestMethod: strings.ToUpper(strings.TrimSpace(raw.RequestMethod)),
		RequestPath:   raw.RequestPath, RequestHost: strings.TrimSpace(raw.RequestHost),
		ResponseStatus: raw.ResponseStatus, ResponseBody: raw.ResponseBody,
		ResponseBodySize: raw.ResponseBodySize, ResponseChunkSize: raw.ResponseChunkSize,
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.Host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if _, _, err := net.SplitHostPort(config.Host); err != nil {
		return fmt.Errorf("host must be host:port: %w", err)
	}
	if config.Threads < 1 || config.Threads > maxThreads {
		return fmt.Errorf("threads must be between 1 and %d", maxThreads)
	}
	if config.TargetTPS < 0 {
		return fmt.Errorf("target_tps must be zero or greater")
	}
	if config.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if config.RampUp < 0 || config.RampUp > config.Duration {
		return fmt.Errorf("ramp_up must be between zero and duration")
	}
	if config.ConnectTimeout <= 0 || config.WriteTimeout <= 0 {
		return fmt.Errorf("connect_timeout and write_timeout must be positive")
	}
	if config.HeartbeatInterval <= 0 || config.StatsInterval <= 0 {
		return fmt.Errorf("heartbeat_interval and stats_interval must be positive")
	}
	if config.ResultsFile == "" {
		return fmt.Errorf("results_file must not be empty")
	}
	if config.AppName == "" {
		return fmt.Errorf("app_name must not be empty")
	}
	if config.ServerID <= 0 {
		return fmt.Errorf("server_id must be positive")
	}
	if config.ClientIP == "" || config.ServerAddress == "" {
		return fmt.Errorf("client_ip and server_address must not be empty")
	}
	if config.RequestMethod == "" || config.RequestPath == "" || config.RequestHost == "" {
		return fmt.Errorf("request_method, request_path, and request_host must not be empty")
	}
	if config.ResponseStatus < 100 || config.ResponseStatus > 599 {
		return fmt.Errorf("response_status must be between 100 and 599")
	}
	if config.ResponseBodySize < 0 {
		return fmt.Errorf("response_body_size must be zero or greater")
	}
	if config.ResponseChunkSize < 0 {
		return fmt.Errorf("response_chunk_size must be zero or greater")
	}
	return nil
}

func (config Config) HighThreadWarning() bool {
	return config.Threads > highThreadWarning
}

func positiveDuration(field, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration: %q", field, value)
	}
	return duration, nil
}

func nonNegativeDuration(field, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("%s must be a nonnegative Go duration: %q", field, value)
	}
	return duration, nil
}
