package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// ====================== 常量定义 ======================
const (
	AUTH_REQUEST    = 1002
	JSON            = 1
	defaultLogFile  = "spa-test-server.log"
	defaultLogLevel = "error"

	maxHTTPRequestBodyBytes = 64 << 10
	maxTokenIDBytes         = 60 << 10
	maxSessionIDBytes       = 40
	maxUsernameBytes        = 256
	maxDeviceIDBytes        = 256
	maxPasswordBytes        = 4 << 10
	maxSPAResponseBodyBytes = 1 << 20
	maxUpstreamBodyBytes    = 1 << 20
)
const (
	QUICDialTimeout     = 3 * time.Second // QUIC连接超时从10秒→3秒
	QUICStreamTimeout   = 2 * time.Second // QUIC流操作超时
	TCPConnectTimeout   = 2 * time.Second // TCP连接超时
	TCPOperationTimeout = 3 * time.Second // TCP操作超时
	MaxIdleTimeout      = 5 * time.Second // 最大空闲超时
)

// ====================== 结构体定义 ======================

// TCP初始化头结构
type TcpInitHeader struct {
	ServerID  int32     // 4字节
	SessionID [40]byte  // 40字节
	UDPSynAck uint32    // 4字节
	DataLen   uint32    // 4字节
	ProtoType uint32    // 4字节
	Version   uint8     // 1字节
	Reserve   uint8     // 1字节
	LocalPort uint16    // 2字节
	AppName   [100]byte // 100字节
}

// SPA协议头结构
type SPAHeader struct {
	Tag       uint32
	Version   uint16
	Command   uint16
	ProtoType uint8
	Option    uint8
	Reserve   uint16
	DataLen   uint32
	OriginLen uint32
}

// TokenInfo 结构体
type TokenInfo struct {
	DevID     string `json:"devid"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Token     string `json:"token"`
}

// 客户端结构体
type Client struct {
	id     int
	config *Config
}

type Config struct {
	Host                         string            `json:"host"`
	Port                         string            `json:"port"`
	ListenAddr                   string            `json:"listen_addr"`
	QUICHost                     string            `json:"quic_host"`
	QUICPort                     string            `json:"quic_port"`
	TLSHost                      string            `json:"tls_host"`
	TLSPort                      string            `json:"tls_port"`
	TLSServerName                string            `json:"tls_server_name"`
	ServerID                     int32             `json:"server_id"`
	AppName                      string            `json:"app_name"`
	LocalPort                    uint16            `json:"local_port"`
	RequestHost                  string            `json:"request_host"`
	RequestPort                  string            `json:"request_port"`
	RequestPath                  string            `json:"request_path"`
	RequestMethod                string            `json:"request_method"`
	RequestHeaders               map[string]string `json:"request_headers"`
	RequestBody                  string            `json:"request_body"`
	UseRawRequest                bool              `json:"use_raw_request"`
	RawRequest                   string            `json:"raw_request"`
	LogFile                      string            `json:"log_file"`
	LogLevel                     string            `json:"log_level"`
	HTTPReadHeaderTimeoutSeconds int               `json:"http_read_header_timeout_s"`
	HTTPReadTimeoutSeconds       int               `json:"http_read_timeout_s"`
	HTTPWriteTimeoutSeconds      int               `json:"http_write_timeout_s"`
	HTTPIdleTimeoutSeconds       int               `json:"http_idle_timeout_s"`
	MaxAuthConcurrency           int               `json:"max_auth_concurrency"`
	MaxProxyConcurrency          int               `json:"max_proxy_concurrency"`
	TCPConnectTimeoutMS          int               `json:"tcp_connect_timeout_ms"`
	TCPOperationTimeoutMS        int               `json:"tcp_operation_timeout_ms"`
	QUICDialTimeoutMS            int               `json:"quic_dial_timeout_ms"`
	QUICStreamTimeoutMS          int               `json:"quic_stream_timeout_ms"`
	ReturnUpstreamBody           bool              `json:"return_upstream_body"`
	UpstreamBodyMaxBytes         int               `json:"upstream_body_max_bytes"`
	BusinessHost                 string            `json:"business_host"`
	BusinessPath                 string            `json:"business_path"`

	RequestBytes []byte `json:"-"`
	AppNameBytes []byte `json:"-"`
}

type App struct {
	config   *Config
	authSem  chan struct{}
	proxySem chan struct{}
	clientID atomic.Int64
}

type authRequest struct {
	Username string `json:"username"`
	DevID    string `json:"devid"`
	Password string `json:"password"`
}

type authResponse struct {
	Success    bool   `json:"success"`
	TokenID    string `json:"token_id"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error"`
}

type proxyRequest struct {
	TokenID   string `json:"token_id"`
	SessionID string `json:"session_id"`
}

type proxyResponse struct {
	Success               bool   `json:"success"`
	DurationMS            int64  `json:"duration_ms"`
	Error                 string `json:"error"`
	UpstreamStatus        string `json:"upstream_status,omitempty"`
	UpstreamStatusCode    int    `json:"upstream_status_code,omitempty"`
	UpstreamBody          string `json:"upstream_body,omitempty"`
	UpstreamBytes         int    `json:"upstream_bytes,omitempty"`
	UpstreamBodyTruncated bool   `json:"upstream_body_truncated"`
}

type BusinessResponse struct {
	Success       bool
	StatusLine    string
	StatusCode    int
	Body          string
	Bytes         int
	BodyTruncated bool
	FailureStage  string
	Error         string
}

// ====================== 工具函数 ======================
// 重写 Marshal 方法避免外部依赖
func (t *TcpInitHeader) Marshal() ([]byte, error) {
	buffer := make([]byte, 160)
	binary.LittleEndian.PutUint32(buffer[0:4], uint32(t.ServerID))
	copy(buffer[4:44], t.SessionID[:])
	binary.LittleEndian.PutUint32(buffer[44:48], t.UDPSynAck)
	binary.LittleEndian.PutUint32(buffer[48:52], t.DataLen)
	binary.LittleEndian.PutUint32(buffer[52:56], t.ProtoType)
	buffer[56] = t.Version
	buffer[57] = t.Reserve
	binary.LittleEndian.PutUint16(buffer[58:60], t.LocalPort)
	copy(buffer[60:160], t.AppName[:])
	return buffer, nil
}

func loadConfig(configPath string) (*Config, error) {
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("无法打开配置文件: %w", err)
	}

	var config Config
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	var rawConfig map[string]json.RawMessage
	if err := json.Unmarshal(configBytes, &rawConfig); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 验证必填字段
	if config.ListenAddr == "" {
		config.ListenAddr = ":8080"
	}
	if config.TLSHost == "" {
		config.TLSHost = config.Host
	}
	if config.TLSPort == "" {
		config.TLSPort = config.Port
	}
	if config.TLSServerName == "" {
		config.TLSServerName = config.TLSHost
	}
	if config.QUICHost == "" {
		return nil, errors.New("配置文件中quic_host字段不能为空")
	}
	if config.QUICPort == "" {
		return nil, errors.New("配置文件中quic_port字段不能为空")
	}
	if config.TLSHost == "" {
		return nil, errors.New("配置文件中tls_host字段不能为空")
	}
	if config.TLSPort == "" {
		return nil, errors.New("配置文件中tls_port字段不能为空")
	}
	if config.ServerID == 0 {
		config.ServerID = 9
	}
	if config.AppName == "" {
		config.AppName = "zjtXh9c5uOY8N7wa"
	}
	if len(config.AppName) > 100 {
		return nil, fmt.Errorf("配置文件中app_name不能超过100字节")
	}
	if config.LocalPort == 0 {
		config.LocalPort = 9090
	}
	if config.RequestHost == "" && config.BusinessHost != "" {
		host, port, err := net.SplitHostPort(config.BusinessHost)
		if err == nil {
			config.RequestHost = host
			config.RequestPort = port
		} else {
			config.RequestHost = config.BusinessHost
		}
	}
	if config.RequestPath == "" && config.BusinessPath != "" {
		config.RequestPath = config.BusinessPath
	}
	if config.RequestHost == "" {
		config.RequestHost = "10.10.27.97"
	}
	if config.RequestPort == "" {
		config.RequestPort = "9090"
	}
	if config.RequestPath == "" {
		config.RequestPath = "/hello"
	}
	if config.RequestMethod == "" {
		config.RequestMethod = "GET"
	}
	if strings.TrimSpace(config.LogFile) == "" {
		config.LogFile = defaultLogFile
	}
	if strings.TrimSpace(config.LogLevel) == "" {
		config.LogLevel = defaultLogLevel
	}
	if _, err := parseLogLevel(config.LogLevel); err != nil {
		return nil, err
	}
	if config.HTTPReadHeaderTimeoutSeconds <= 0 {
		config.HTTPReadHeaderTimeoutSeconds = 2
	}
	if config.HTTPReadTimeoutSeconds <= 0 {
		config.HTTPReadTimeoutSeconds = 5
	}
	if config.HTTPWriteTimeoutSeconds <= 0 {
		config.HTTPWriteTimeoutSeconds = 15
	}
	if config.HTTPIdleTimeoutSeconds <= 0 {
		config.HTTPIdleTimeoutSeconds = 60
	}
	if config.MaxAuthConcurrency <= 0 {
		config.MaxAuthConcurrency = 1000
	}
	if config.MaxProxyConcurrency <= 0 {
		config.MaxProxyConcurrency = 12000
	}
	if config.TCPConnectTimeoutMS <= 0 {
		config.TCPConnectTimeoutMS = int(TCPConnectTimeout / time.Millisecond)
	}
	if config.TCPOperationTimeoutMS <= 0 {
		config.TCPOperationTimeoutMS = int(TCPOperationTimeout / time.Millisecond)
	}
	if config.QUICDialTimeoutMS <= 0 {
		config.QUICDialTimeoutMS = int(QUICDialTimeout / time.Millisecond)
	}
	if config.QUICStreamTimeoutMS <= 0 {
		config.QUICStreamTimeoutMS = int(QUICStreamTimeout / time.Millisecond)
	}
	if _, ok := rawConfig["return_upstream_body"]; !ok {
		config.ReturnUpstreamBody = true
	}
	if config.UpstreamBodyMaxBytes <= 0 {
		config.UpstreamBodyMaxBytes = 4096
	}
	if config.UpstreamBodyMaxBytes > maxUpstreamBodyBytes {
		return nil, fmt.Errorf("upstream_body_max_bytes不能超过%d", maxUpstreamBodyBytes)
	}
	config.RequestBytes, err = buildRequestBytes(&config)
	if err != nil {
		return nil, err
	}
	config.AppNameBytes = []byte(config.AppName)

	return &config, nil
}

func buildRequestBytes(config *Config) ([]byte, error) {
	if config.UseRawRequest {
		if config.RawRequest == "" {
			return nil, fmt.Errorf("use_raw_request 为 true 时 raw_request 不能为空")
		}
		return []byte(config.RawRequest), nil
	}

	method := strings.ToUpper(strings.TrimSpace(config.RequestMethod))
	if method == "" {
		method = "GET"
	}
	path := strings.TrimSpace(config.RequestPath)
	if path == "" {
		path = "/"
	}

	headers := make(map[string]string, len(config.RequestHeaders)+4)
	setHeader(headers, "Host", requestHostHeader(config.RequestHost, config.RequestPort))
	setHeader(headers, "User-Agent", "curl/7.68.0")
	setHeader(headers, "Accept", "*/*")
	setHeader(headers, "Connection", "close")
	for key, value := range config.RequestHeaders {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		setHeader(headers, key, value)
	}
	if config.RequestBody != "" {
		setHeader(headers, "Content-Length", fmt.Sprintf("%d", len([]byte(config.RequestBody))))
	}

	var builder strings.Builder
	builder.Grow(len(config.RequestBody) + 256 + len(headers)*32)
	fmt.Fprintf(&builder, "%s %s HTTP/1.1\r\n", method, path)

	preferredHeaders := []string{"Host", "User-Agent", "Accept", "Connection", "Content-Length"}
	written := make(map[string]struct{}, len(headers))
	for _, key := range preferredHeaders {
		actualKey, ok := findHeaderKey(headers, key)
		if !ok {
			continue
		}
		fmt.Fprintf(&builder, "%s: %s\r\n", actualKey, headers[actualKey])
		written[strings.ToLower(actualKey)] = struct{}{}
	}

	headerKeys := make([]string, 0, len(headers)-len(written))
	for key := range headers {
		if _, ok := written[strings.ToLower(key)]; ok {
			continue
		}
		headerKeys = append(headerKeys, key)
	}
	sort.Slice(headerKeys, func(i, j int) bool {
		return strings.ToLower(headerKeys[i]) < strings.ToLower(headerKeys[j])
	})
	for _, key := range headerKeys {
		fmt.Fprintf(&builder, "%s: %s\r\n", key, headers[key])
	}

	builder.WriteString("\r\n")
	builder.WriteString(config.RequestBody)
	return []byte(builder.String()), nil
}

func requestHostHeader(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" || port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func setHeader(headers map[string]string, key, value string) {
	if existingKey, ok := findHeaderKey(headers, key); ok {
		delete(headers, existingKey)
	}
	headers[key] = value
}

func findHeaderKey(headers map[string]string, key string) (string, bool) {
	for existingKey := range headers {
		if strings.EqualFold(existingKey, key) {
			return existingKey, true
		}
	}
	return "", false
}

// ====================== TCP 客户端功能 ======================
func failedBusinessResponse(stage string, err error) BusinessResponse {
	return BusinessResponse{FailureStage: stage, Error: err.Error()}
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func (c *Client) runTCPClient(ctx context.Context, host, port, tokenID, sessionID string) BusinessResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(sessionID) == "" {
		return failedBusinessResponse("validation", errors.New("session_id不能为空"))
	}

	if strings.TrimSpace(tokenID) == "" {
		return failedBusinessResponse("validation", errors.New("token_id不能为空"))
	}

	// 连接服务器
	address := net.JoinHostPort(host, port)
	dialer := net.Dialer{
		Timeout:   tcpConnectTimeout(c.config),
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return failedBusinessResponse("tcp_connect", contextError(ctx, err))
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	slog.Debug("proxy stage completed", "event", "proxy_stage", "client_id", c.id, "stage", "tcp_connect", "tls", address)
	_ = conn.SetDeadline(operationDeadline(ctx, tcpOperationTimeout(c.config)))
	// 创建 utls config
	serverName := host
	if c.config != nil && c.config.TLSServerName != "" {
		serverName = c.config.TLSServerName
	}
	config := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}

	tokenData := tokenID

	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_RSA_WITH_RC4_128_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: serverName},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
			&utls.GenericExtension{
				Id:   15001,
				Data: []byte(tokenData),
			},
		},
	}

	uconn := utls.UClient(conn, config, utls.HelloCustom)

	if err := uconn.ApplyPreset(spec); err != nil {
		return failedBusinessResponse("tls_client_hello", err)
	}

	err = uconn.HandshakeContext(ctx)
	if err != nil {
		return failedBusinessResponse("tls_handshake", contextError(ctx, err))
	}
	slog.Debug("proxy stage completed", "event", "proxy_stage", "client_id", c.id, "stage", "tls_handshake", "tls", address)

	// 创建并填充头结构
	serverID := int32(9)
	localPort := uint16(9090)
	appNameBytes := []byte("zjtXh9c5uOY8N7wa")
	if c.config != nil {
		if c.config.ServerID != 0 {
			serverID = c.config.ServerID
		}
		if c.config.LocalPort != 0 {
			localPort = c.config.LocalPort
		}
		if len(c.config.AppNameBytes) > 0 {
			appNameBytes = c.config.AppNameBytes
		} else if c.config.AppName != "" {
			appNameBytes = []byte(c.config.AppName)
		}
	}
	header := TcpInitHeader{
		ServerID:  serverID,
		UDPSynAck: 0,
		DataLen:   160,
		ProtoType: 1,
		Version:   1,
		Reserve:   0,
		LocalPort: localPort,
	}

	sessionIDStr := sessionID
	copy(header.SessionID[:], []byte(sessionIDStr))

	copy(header.AppName[:], appNameBytes)

	bytesRequest, err := header.Marshal()
	if err != nil {
		return failedBusinessResponse("gateway_header_encode", err)
	}

	if err = writeAll(uconn, bytesRequest); err != nil {
		return failedBusinessResponse("gateway_header_write", err)
	}

	// 读取并解析服务器响应
	_ = uconn.SetReadDeadline(operationDeadline(ctx, tcpOperationTimeout(c.config)))
	response := make([]byte, 20)
	n, err := io.ReadFull(uconn, response)
	if err != nil {
		return failedBusinessResponse("gateway_header_read", contextError(ctx, err))
	}

	if n < 20 {
		return failedBusinessResponse("gateway_header_read", fmt.Errorf("接收数据不足: %d 字节，需要至少20字节", n))
	}
	slog.Debug("proxy stage completed", "event", "proxy_stage", "client_id", c.id, "stage", "gateway_init", "response_bytes", n)

	// 发送业务请求
	return c.sendTCPHello(uconn)
}

// 发送第三方业务请求
func (c *Client) sendTCPHello(conn net.Conn) BusinessResponse {
	requestBytes := []byte("GET /hello HTTP/1.0\r\n" +
		"Host: 10.10.27.97:9090\r\n" +
		"User-Agent: curl/7.68.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n")
	if c.config != nil {
		if len(c.config.RequestBytes) > 0 {
			requestBytes = c.config.RequestBytes
		} else if requestBytesFromConfig, err := buildRequestBytes(c.config); err == nil {
			requestBytes = requestBytesFromConfig
		}
	}

	if deadlineConn, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetWriteDeadline(time.Now().Add(tcpOperationTimeout(c.config)))
	}
	if err := writeAll(conn, requestBytes); err != nil {
		return failedBusinessResponse("business_request_write", err)
	}

	if deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetReadDeadline(time.Now().Add(tcpOperationTimeout(c.config)))
	}
	result := readBusinessHTTPResponse(conn, c.config)
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug("upstream response", "event", "upstream_response", "client_id", c.id, "status", result.StatusLine, "body_bytes", result.Bytes, "body_truncated", result.BodyTruncated, "body", result.Body)
	}
	if c.config != nil && !c.config.ReturnUpstreamBody {
		result.Body = ""
		result.BodyTruncated = false
	}
	if result.FailureStage != "" {
		return result
	}
	if result.Success {
		return result
	}
	result.FailureStage = "business_response"
	if result.StatusLine != "" {
		result.Error = fmt.Sprintf("上游返回非成功状态: %s", result.StatusLine)
	} else {
		result.Error = "上游响应格式无效"
	}
	return result
}

func readBusinessHTTPResponse(conn net.Conn, config *Config) BusinessResponse {
	response, err := http.ReadResponse(bufio.NewReaderSize(conn, 4096), nil)
	if err != nil {
		return failedBusinessResponse("business_response_read", err)
	}

	result := BusinessResponse{
		Success:    response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices,
		StatusLine: response.Proto + " " + response.Status,
		StatusCode: response.StatusCode,
	}
	readBody := config == nil || config.ReturnUpstreamBody || slog.Default().Enabled(context.Background(), slog.LevelDebug)
	if !readBody {
		_ = conn.Close()
		_ = response.Body.Close()
		return result
	}

	maxBytes := 4096
	if config != nil && config.UpstreamBodyMaxBytes > 0 {
		maxBytes = config.UpstreamBodyMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	if err != nil {
		_ = conn.Close()
		_ = response.Body.Close()
		result.FailureStage = "business_response_read"
		result.Error = err.Error()
		return result
	}
	if len(body) > maxBytes {
		body = body[:maxBytes]
		result.BodyTruncated = true
		_ = conn.Close()
	}
	_ = response.Body.Close()
	result.Bytes = len(body)
	result.Body = string(body)
	return result
}

func tokenPreview(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= 12 {
		return "[REDACTED]"
	}
	return token[:6] + "..." + token[len(token)-6:]
}

func NewApp(config *Config) *App {
	app := &App{config: config}
	if config != nil && config.MaxAuthConcurrency > 0 {
		app.authSem = make(chan struct{}, config.MaxAuthConcurrency)
	}
	if config != nil && config.MaxProxyConcurrency > 0 {
		app.proxySem = make(chan struct{}, config.MaxProxyConcurrency)
	}
	return app
}

func (a *App) tryAcquire(sem chan struct{}) bool {
	if sem == nil {
		return true
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *App) release(sem chan struct{}) {
	if sem == nil {
		return
	}
	<-sem
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", a.handleAuth)
	mux.HandleFunc("/proxy", a.handleProxy)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

func (a *App) handleAuth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		slog.Error("auth request failed", "event", "auth_failed", "status", http.StatusMethodNotAllowed, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "error", "method not allowed")
		writeJSON(w, http.StatusMethodNotAllowed, authResponse{Success: false, Error: "method not allowed"})
		return
	}

	var request authRequest
	if err := decodeJSON(w, r, &request); err != nil {
		status := jsonErrorStatus(err)
		slog.Error("auth request failed", "event", "auth_failed", "status", status, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "error", err)
		writeJSON(w, status, authResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	request.DevID = strings.TrimSpace(request.DevID)
	if request.Username == "" {
		slog.Error("auth request failed", "event", "auth_failed", "status", http.StatusBadRequest, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "devid", request.DevID, "error", "username不能为空")
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: "username不能为空"})
		return
	}
	if request.DevID == "" {
		slog.Error("auth request failed", "event", "auth_failed", "status", http.StatusBadRequest, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "username", request.Username, "error", "devid不能为空")
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: "devid不能为空"})
		return
	}
	if len(request.Username) > maxUsernameBytes {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: fmt.Sprintf("username不能超过%d字节", maxUsernameBytes)})
		return
	}
	if len(request.DevID) > maxDeviceIDBytes {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: fmt.Sprintf("devid不能超过%d字节", maxDeviceIDBytes)})
		return
	}
	if len(request.Password) > maxPasswordBytes {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: fmt.Sprintf("password不能超过%d字节", maxPasswordBytes)})
		return
	}
	if err := validateAuthPassword(request.Password); err != nil {
		slog.Error("auth request failed", "event", "auth_failed", "status", http.StatusBadRequest, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "username", request.Username, "devid", request.DevID, "error", err)
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}

	if !a.tryAcquire(a.authSem) {
		slog.Error("auth request failed", "event", "auth_failed", "status", http.StatusTooManyRequests, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "username", request.Username, "devid", request.DevID, "error", "too many auth requests")
		writeJSON(w, http.StatusTooManyRequests, authResponse{Success: false, DurationMS: elapsedMS(start), Error: "too many auth requests"})
		return
	}
	defer a.release(a.authSem)
	slog.Debug("auth request accepted", "event", "auth_request", "remote", r.RemoteAddr, "username", request.Username, "devid", request.DevID)

	tokenID, err := a.runQUICAuth(r.Context(), request)
	if err != nil {
		slog.Error("auth request failed", "event", "auth_failed", "status", http.StatusBadGateway, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "username", request.Username, "devid", request.DevID, "quic", net.JoinHostPort(a.config.QUICHost, a.config.QUICPort), "error", err)
		writeJSON(w, http.StatusBadGateway, authResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}
	slog.Info("auth request succeeded", "event", "auth_success", "status", http.StatusOK, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "username", request.Username, "devid", request.DevID)
	writeJSON(w, http.StatusOK, authResponse{Success: true, TokenID: tokenID, DurationMS: elapsedMS(start)})
}

func (a *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		slog.Error("proxy request failed", "event", "proxy_failed", "status", http.StatusMethodNotAllowed, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "error", "method not allowed")
		writeJSON(w, http.StatusMethodNotAllowed, proxyResponse{Success: false, Error: "method not allowed"})
		return
	}

	var request proxyRequest
	if err := decodeJSON(w, r, &request); err != nil {
		status := jsonErrorStatus(err)
		slog.Error("proxy request failed", "event", "proxy_failed", "status", status, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "error", err)
		writeJSON(w, status, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}
	request.TokenID = strings.TrimSpace(request.TokenID)
	request.SessionID = strings.TrimSpace(request.SessionID)
	if request.TokenID == "" {
		slog.Error("proxy request failed", "event", "proxy_failed", "status", http.StatusBadRequest, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "session_id", request.SessionID, "error", "token_id不能为空")
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: "token_id不能为空"})
		return
	}
	if request.SessionID == "" {
		slog.Error("proxy request failed", "event", "proxy_failed", "status", http.StatusBadRequest, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "token", tokenPreview(request.TokenID), "error", "session_id不能为空")
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: "session_id不能为空"})
		return
	}
	if len(request.TokenID) > maxTokenIDBytes {
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: fmt.Sprintf("token_id不能超过%d字节", maxTokenIDBytes)})
		return
	}
	if len(request.SessionID) > maxSessionIDBytes {
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: fmt.Sprintf("session_id不能超过%d字节", maxSessionIDBytes)})
		return
	}

	if !a.tryAcquire(a.proxySem) {
		slog.Error("proxy request failed", "event", "proxy_failed", "status", http.StatusTooManyRequests, "duration_ms", elapsedMS(start), "remote", r.RemoteAddr, "session_id", request.SessionID, "token", tokenPreview(request.TokenID), "error", "too many proxy requests")
		writeJSON(w, http.StatusTooManyRequests, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: "too many proxy requests"})
		return
	}
	defer a.release(a.proxySem)
	logger := slog.Default()
	if logger.Enabled(r.Context(), slog.LevelDebug) {
		logger.DebugContext(r.Context(), "proxy request accepted", "event", "proxy_request", "remote", r.RemoteAddr, "session_id", request.SessionID, "token", tokenPreview(request.TokenID))
	}

	client := &Client{id: int(a.clientID.Add(1)), config: a.config}
	upstream := client.runTCPClient(r.Context(), a.config.TLSHost, a.config.TLSPort, request.TokenID, request.SessionID)
	response := proxyResponse{
		Success:               upstream.Success,
		DurationMS:            elapsedMS(start),
		UpstreamStatus:        upstream.StatusLine,
		UpstreamStatusCode:    upstream.StatusCode,
		UpstreamBody:          upstream.Body,
		UpstreamBytes:         upstream.Bytes,
		UpstreamBodyTruncated: upstream.BodyTruncated,
	}
	if !upstream.Success {
		response.Error = "proxy request failed"
		slog.Error("proxy request failed", "event", "proxy_failed", "status", http.StatusBadGateway, "duration_ms", response.DurationMS, "remote", r.RemoteAddr, "session_id", request.SessionID, "token", tokenPreview(request.TokenID), "tls", net.JoinHostPort(a.config.TLSHost, a.config.TLSPort), "failure_stage", upstream.FailureStage, "upstream_status_code", upstream.StatusCode, "upstream_status", upstream.StatusLine, "upstream_bytes", upstream.Bytes, "error", upstream.Error)
		writeJSON(w, http.StatusBadGateway, response)
		return
	}
	if logger.Enabled(r.Context(), slog.LevelInfo) {
		logger.InfoContext(r.Context(), "proxy request succeeded", "event", "proxy_success", "status", http.StatusOK, "duration_ms", response.DurationMS, "remote", r.RemoteAddr, "session_id", request.SessionID, "token", tokenPreview(request.TokenID), "upstream_status_code", upstream.StatusCode, "upstream_bytes", upstream.Bytes)
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) runQUICAuth(ctx context.Context, request authRequest) (string, error) {
	if a.config == nil {
		return "", errors.New("服务配置为空")
	}
	address := net.JoinHostPort(a.config.QUICHost, a.config.QUICPort)
	authRequest := map[string]interface{}{
		"requestid":      uuid.New().String(),
		"devid":          request.DevID,
		"username":       request.Username,
		"password":       request.Password,
		"authType":       0,
		"strpackagename": "com.leagsoft.emm",
		"codetype":       "0",
		"Version":        "5.4",
	}
	return sendSPARequest(ctx, address, authRequest, request.DevID, a.config)
}

func validateAuthPassword(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return errors.New("password不能为空，请在/auth请求体传入password")
	}
	if strings.EqualFold(password, "optional") || strings.EqualFold(password, "replace-with-password") {
		return errors.New("password不能使用示例占位值，请传入真实认证密码")
	}
	return nil
}

func sendSPARequest(ctx context.Context, address string, authRequest map[string]interface{}, devid string, config *Config) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos: []string{
			"hq-interop", "h3-23", "h3-24", "h3-25", "hq-29", "hq-28", "hq-27", "http/0.9",
		},
	}
	quicConfig := &quic.Config{
		KeepAlivePeriod: 5 * time.Second,
		MaxIdleTimeout:  MaxIdleTimeout,
	}

	dialCtx, cancel := context.WithTimeout(ctx, quicDialTimeout(config))
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, address, tlsConfig, quicConfig)
	if err != nil {
		return "", fmt.Errorf("连接失败: %w", contextError(ctx, err))
	}
	defer conn.CloseWithError(0, "client closed")
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(1, "request canceled") })
	defer stopCancel()

	streamTimeout := quicStreamTimeout(config)
	streamCtx, streamCancel := context.WithTimeout(ctx, streamTimeout)
	defer streamCancel()
	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		return "", fmt.Errorf("打开流失败: %w", err)
	}
	defer stream.Close()

	if err := sendQUICAuthRequest(stream, authRequest, streamTimeout); err != nil {
		return "", fmt.Errorf("发送请求失败: %w", err)
	}

	response, err := receiveSPAResponse(stream, streamTimeout)
	if err != nil {
		return "", fmt.Errorf("接收响应失败: %w", err)
	}
	return encodeTokenID(response, devid)
}

func encodeTokenID(response map[string]interface{}, devid string) (string, error) {
	timestamp, ok := response["timestamp"]
	if !ok {
		return "", fmt.Errorf("timestamp 字段缺失，上游响应: %s", compactJSON(response))
	}

	var timestampInt int64
	switch v := timestamp.(type) {
	case float64:
		timestampInt = int64(v)
	case int64:
		timestampInt = v
	case int:
		timestampInt = int64(v)
	case json.Number:
		ts, err := v.Int64()
		if err != nil {
			return "", fmt.Errorf("timestamp 类型转换失败: %w", err)
		}
		timestampInt = ts
	default:
		return "", fmt.Errorf("timestamp 类型错误: %T", v)
	}

	nonce, ok := response["nonce"].(string)
	if !ok {
		return "", fmt.Errorf("nonce 字段缺失或类型错误，上游响应: %s", compactJSON(response))
	}
	token, ok := response["token"].(string)
	if !ok {
		return "", fmt.Errorf("token 字段缺失或类型错误，上游响应: %s", compactJSON(response))
	}

	info := TokenInfo{
		DevID:     devid,
		Timestamp: timestampInt,
		Nonce:     nonce,
		Token:     token,
	}
	jsonData, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("序列化 token 信息失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(jsonData), nil
}

func compactJSON(value interface{}) string {
	data, err := json.Marshal(redactSensitiveFields(value))
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
}

func redactSensitiveFields(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		redacted := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			if strings.EqualFold(key, "token") || strings.EqualFold(key, "password") {
				redacted[key] = "[REDACTED]"
				continue
			}
			redacted[key] = redactSensitiveFields(item)
		}
		return redacted
	case []interface{}:
		redacted := make([]interface{}, len(typed))
		for i, item := range typed {
			redacted[i] = redactSensitiveFields(item)
		}
		return redacted
	default:
		return value
	}
}

func sendQUICAuthRequest(stream *quic.Stream, authRequest map[string]interface{}, timeout time.Duration) error {
	bodyBytes, err := json.Marshal(authRequest)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %w", err)
	}

	headerBytes := make([]byte, 20)
	binary.BigEndian.PutUint32(headerBytes[0:4], 0x5350413A)
	binary.BigEndian.PutUint16(headerBytes[4:6], 1)
	binary.BigEndian.PutUint16(headerBytes[6:8], AUTH_REQUEST)
	headerBytes[8] = JSON
	headerBytes[9] = 0
	binary.BigEndian.PutUint16(headerBytes[10:12], 0)
	binary.BigEndian.PutUint32(headerBytes[12:16], uint32(len(bodyBytes)))
	binary.BigEndian.PutUint32(headerBytes[16:20], 0)

	if err := stream.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := writeAll(stream, headerBytes); err != nil {
		return fmt.Errorf("发送消息头失败: %w", err)
	}
	if err := writeAll(stream, bodyBytes); err != nil {
		return fmt.Errorf("发送消息体失败: %w", err)
	}
	return nil
}

type readDeadlineReader interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

func receiveSPAResponse(stream readDeadlineReader, timeout time.Duration) (map[string]interface{}, error) {
	if err := stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("设置读取超时失败: %w", err)
	}

	headerBytes := make([]byte, 20)
	if _, err := io.ReadFull(stream, headerBytes); err != nil {
		return nil, fmt.Errorf("读取响应头失败: %w", err)
	}

	header := SPAHeader{
		Tag:       binary.BigEndian.Uint32(headerBytes[0:4]),
		Version:   binary.BigEndian.Uint16(headerBytes[4:6]),
		Command:   binary.BigEndian.Uint16(headerBytes[6:8]),
		ProtoType: headerBytes[8],
		Option:    headerBytes[9],
		Reserve:   binary.BigEndian.Uint16(headerBytes[10:12]),
		DataLen:   binary.BigEndian.Uint32(headerBytes[12:16]),
		OriginLen: binary.BigEndian.Uint32(headerBytes[16:20]),
	}
	if header.Tag != 0x5350413A {
		return nil, fmt.Errorf("SPA响应Tag无效: 0x%08x", header.Tag)
	}
	if header.Version != 1 {
		return nil, fmt.Errorf("SPA响应Version无效: %d", header.Version)
	}
	if header.DataLen == 0 {
		return nil, errors.New("响应体长度为0")
	}
	if header.DataLen > maxSPAResponseBodyBytes {
		return nil, fmt.Errorf("响应体长度%d超过上限%d", header.DataLen, maxSPAResponseBodyBytes)
	}

	bodyBytes := make([]byte, header.DataLen)
	if _, err := io.ReadFull(stream, bodyBytes); err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return map[string]interface{}{
			"raw_data_hex": fmt.Sprintf("%x", bodyBytes),
			"raw_data_str": string(bodyBytes),
			"data_length":  len(bodyBytes),
			"parse_error":  err.Error(),
		}, nil
	}
	return body, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxHTTPRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("解析JSON失败: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("解析JSON失败: 请求体只能包含一个JSON对象")
		}
		return fmt.Errorf("解析JSON失败: %w", err)
	}
	return nil
}

func jsonErrorStatus(err error) int {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write HTTP response failed", "event", "http_response_write_failed", "status", status, "error", err)
	}
}

func elapsedMS(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func operationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctx != nil {
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			return contextDeadline
		}
	}
	return deadline
}

func contextError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func isHelpArg(arg string) bool {
	return arg == "-h" || arg == "--help"
}

func printUsage() {
	fmt.Fprintf(os.Stdout, "Usage: SPA-test-server [--help]\n\n")
	fmt.Fprintf(os.Stdout, "Starts an HTTP service for JMeter:\n")
	fmt.Fprintf(os.Stdout, "  POST /auth  - QUIC authentication, returns token_id\n")
	fmt.Fprintf(os.Stdout, "  POST /proxy - TLS gateway request using token_id and session_id\n")
}

func setupLogger(config *Config) (io.Closer, error) {
	logFile := defaultLogFile
	logLevel := defaultLogLevel
	if config != nil {
		if strings.TrimSpace(config.LogFile) != "" {
			logFile = strings.TrimSpace(config.LogFile)
		}
		if strings.TrimSpace(config.LogLevel) != "" {
			logLevel = strings.TrimSpace(config.LogLevel)
		}
	}

	level, err := parseLogLevel(logLevel)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开日志文件失败: %w", err)
	}
	sink := newAsyncLogSink(file, 8192)
	slog.SetDefault(slog.New(newColumnLogHandler(sink, level)))
	return sink, nil
}

type asyncLogSink struct {
	writer    io.WriteCloser
	queue     chan []byte
	done      chan struct{}
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
	dropped   atomic.Uint64
}

func newAsyncLogSink(writer io.WriteCloser, queueSize int) *asyncLogSink {
	if queueSize < 1 {
		queueSize = 1
	}
	sink := &asyncLogSink{
		writer: writer,
		queue:  make(chan []byte, queueSize),
		done:   make(chan struct{}),
	}
	go sink.run()
	return sink
}

func (s *asyncLogSink) Write(data []byte) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, os.ErrClosed
	}
	line := append([]byte(nil), data...)
	select {
	case s.queue <- line:
	default:
		s.dropped.Add(1)
	}
	return len(data), nil
}

func (s *asyncLogSink) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
		<-s.done
		s.closeErr = s.writer.Close()
	})
	return s.closeErr
}

func (s *asyncLogSink) run() {
	defer close(s.done)
	buffered := bufio.NewWriterSize(s.writer, 64<<10)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case line, ok := <-s.queue:
			if !ok {
				s.writeDroppedSummary(buffered)
				_ = buffered.Flush()
				return
			}
			_, _ = buffered.Write(line)
		case <-ticker.C:
			s.writeDroppedSummary(buffered)
			_ = buffered.Flush()
		}
	}
}

func (s *asyncLogSink) writeDroppedSummary(writer io.Writer) {
	dropped := s.dropped.Swap(0)
	if dropped == 0 {
		return
	}
	_, _ = fmt.Fprintf(writer, "%s      warn    SPA-test-server/logger:0             log queue full event=log_dropped count=%d\n", time.Now().Format("2006-01-02 15:04:05.000000"), dropped)
}

type columnLogHandler struct {
	writer io.Writer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

func newColumnLogHandler(writer io.Writer, level slog.Level) *columnLogHandler {
	return &columnLogHandler{writer: writer, level: level}
}

func (h *columnLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *columnLogHandler) Handle(_ context.Context, record slog.Record) error {
	timestamp := record.Time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "%s      %-7s %-36s %s",
		timestamp.Format("2006-01-02 15:04:05.000000"),
		strings.ToLower(record.Level.String()),
		logSource(record.PC),
		record.Message,
	)
	for _, attr := range h.attrs {
		appendLogAttr(&builder, h.groups, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		appendLogAttr(&builder, h.groups, attr)
		return true
	})
	builder.WriteByte('\n')

	_, err := io.WriteString(h.writer, builder.String())
	return err
}

func (h *columnLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	clone.groups = append([]string(nil), h.groups...)
	return &clone
}

func (h *columnLogHandler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.attrs = append([]slog.Attr(nil), h.attrs...)
	clone.groups = append(append([]string(nil), h.groups...), name)
	return &clone
}

func appendLogAttr(builder *strings.Builder, groups []string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return
	}
	if attr.Value.Kind() == slog.KindGroup {
		nestedGroups := groups
		if attr.Key != "" {
			nestedGroups = append(append([]string(nil), groups...), attr.Key)
		}
		for _, nested := range attr.Value.Group() {
			appendLogAttr(builder, nestedGroups, nested)
		}
		return
	}

	keyParts := append([]string(nil), groups...)
	if attr.Key != "" {
		keyParts = append(keyParts, attr.Key)
	}
	if len(keyParts) == 0 {
		return
	}
	fmt.Fprintf(builder, " %s=%s", strings.Join(keyParts, "."), formatLogValue(attr.Value))
}

func formatLogValue(value slog.Value) string {
	var text string
	switch value.Kind() {
	case slog.KindString:
		text = value.String()
	case slog.KindTime:
		text = value.Time().Format(time.RFC3339Nano)
	case slog.KindDuration:
		text = value.Duration().String()
	default:
		text = fmt.Sprint(value.Any())
	}
	if text == "" || strings.ContainsAny(text, " \t\r\n\"=") {
		return strconv.Quote(text)
	}
	return text
}

func logSource(pc uintptr) string {
	frame, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	if frame.File == "" {
		return "unknown:0"
	}
	return filepath.Join(filepath.Base(filepath.Dir(frame.File)), filepath.Base(frame.File)) + ":" + strconv.Itoa(frame.Line)
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "":
		return slog.LevelError, nil
	default:
		return slog.LevelError, fmt.Errorf("log_level %q 无效，可选值: error, warn, info, debug", value)
	}
}

func tcpConnectTimeout(config *Config) time.Duration {
	return durationFromMilliseconds(configValue(config, func(c *Config) int {
		return c.TCPConnectTimeoutMS
	}), TCPConnectTimeout)
}

func tcpOperationTimeout(config *Config) time.Duration {
	return durationFromMilliseconds(configValue(config, func(c *Config) int {
		return c.TCPOperationTimeoutMS
	}), TCPOperationTimeout)
}

func quicDialTimeout(config *Config) time.Duration {
	return durationFromMilliseconds(configValue(config, func(c *Config) int {
		return c.QUICDialTimeoutMS
	}), QUICDialTimeout)
}

func quicStreamTimeout(config *Config) time.Duration {
	return durationFromMilliseconds(configValue(config, func(c *Config) int {
		return c.QUICStreamTimeoutMS
	}), QUICStreamTimeout)
}

func durationFromMilliseconds(value int, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func durationFromSeconds(value int, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Second
}

func configValue(config *Config, getter func(*Config) int) int {
	if config == nil {
		return 0
	}
	return getter(config)
}

func newHTTPServer(config *Config, handler http.Handler) *http.Server {
	addr := ":8080"
	if config != nil && config.ListenAddr != "" {
		addr = config.ListenAddr
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: durationFromSeconds(configValue(config, func(c *Config) int { return c.HTTPReadHeaderTimeoutSeconds }), 2*time.Second),
		ReadTimeout:       durationFromSeconds(configValue(config, func(c *Config) int { return c.HTTPReadTimeoutSeconds }), 5*time.Second),
		WriteTimeout:      durationFromSeconds(configValue(config, func(c *Config) int { return c.HTTPWriteTimeoutSeconds }), 15*time.Second),
		IdleTimeout:       durationFromSeconds(configValue(config, func(c *Config) int { return c.HTTPIdleTimeoutSeconds }), 60*time.Second),
		ErrorLog:          log.New(slogWriter{level: slog.LevelError}, "", 0),
	}
}

type slogWriter struct {
	level slog.Level
}

func (w slogWriter) Write(data []byte) (int, error) {
	message := strings.TrimSpace(string(data))
	if message != "" {
		slog.Log(context.Background(), w.level, message, "event", "http_server_error")
	}
	return len(data), nil
}

func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener, shutdownTimeout time.Duration) error {
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	select {
	case err := <-serveDone:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		serveErr := <-serveDone
		if shutdownErr != nil {
			_ = server.Close()
			return shutdownErr
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
}

// ====================== 主函数 ======================
func main() {
	if len(os.Args) > 1 && isHelpArg(os.Args[1]) {
		printUsage()
		return
	}

	bootstrapCloser, err := setupLogger(nil)
	if err != nil {
		os.Exit(1)
	}

	config, err := loadConfig("config.json")
	if err != nil {
		slog.Error("load configuration failed", "event", "config_load_failed", "error", err)
		_ = bootstrapCloser.Close()
		os.Exit(1)
	}
	logCloser, err := setupLogger(config)
	if err != nil {
		slog.Error("initialize logger failed", "event", "logger_init_failed", "log_file", config.LogFile, "log_level", config.LogLevel, "error", err)
		_ = bootstrapCloser.Close()
		os.Exit(1)
	}
	_ = bootstrapCloser.Close()
	defer logCloser.Close()

	app := NewApp(config)
	slog.Info("HTTP service starting", "event", "server_start", "listen", config.ListenAddr, "quic", net.JoinHostPort(config.QUICHost, config.QUICPort), "tls", net.JoinHostPort(config.TLSHost, config.TLSPort), "request_method", strings.ToUpper(config.RequestMethod), "request_target", net.JoinHostPort(config.RequestHost, config.RequestPort)+config.RequestPath, "log_file", config.LogFile, "log_level", config.LogLevel)
	server := newHTTPServer(config, app.routes())
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		slog.Error("HTTP service failed to listen", "event", "server_listen_failed", "listen", config.ListenAddr, "error", err)
		_ = logCloser.Close()
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveHTTP(ctx, server, listener, 15*time.Second); err != nil {
		slog.Error("HTTP service stopped", "event", "server_stopped", "listen", config.ListenAddr, "error", err)
		_ = logCloser.Close()
		os.Exit(1)
	}
	slog.Info("HTTP service stopped", "event", "server_stopped", "listen", config.ListenAddr)
}
