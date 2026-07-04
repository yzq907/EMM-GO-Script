package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

// ====================== 常量定义 ======================
const (
	AUTH_REQUEST = 1002
	JSON         = 1
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
	id         int
	config     *Config
	bufferPool *sync.Pool
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
	DebugResponse                bool              `json:"debug_response"`
	DebugResponseMaxBytes        int               `json:"debug_response_max_bytes"`
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
	ReadLimit    int    `json:"-"`
	AppNameBytes []byte `json:"-"`
}

type App struct {
	config     *Config
	authSem    chan struct{}
	proxySem   chan struct{}
	bufferPool *sync.Pool
	clientID   atomic.Int64
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
	Success            bool   `json:"success"`
	DurationMS         int64  `json:"duration_ms"`
	Error              string `json:"error"`
	UpstreamStatus     string `json:"upstream_status,omitempty"`
	UpstreamStatusCode int    `json:"upstream_status_code,omitempty"`
	UpstreamBody       string `json:"upstream_body,omitempty"`
	UpstreamBytes      int    `json:"upstream_bytes,omitempty"`
}

type BusinessResponse struct {
	Success    bool
	StatusLine string
	StatusCode int
	Body       string
	Bytes      int
}

// ====================== 工具函数 ======================
// 重写 Marshal 方法避免外部依赖
func (t *TcpInitHeader) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// 按小端序写入各字段
	if err := binary.Write(buf, binary.LittleEndian, t.ServerID); err != nil {
		return nil, err
	}
	if _, err := buf.Write(t.SessionID[:]); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, t.UDPSynAck); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, t.DataLen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, t.ProtoType); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, t.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, t.Reserve); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, t.LocalPort); err != nil {
		return nil, err
	}
	if _, err := buf.Write(t.AppName[:]); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
	if config.DebugResponseMaxBytes <= 0 {
		config.DebugResponseMaxBytes = 4096
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
		config.UpstreamBodyMaxBytes = config.DebugResponseMaxBytes
	}
	if config.ReturnUpstreamBody {
		config.ReadLimit = config.UpstreamBodyMaxBytes
	} else {
		config.ReadLimit = 1024
	}
	if config.DebugResponse {
		config.ReadLimit = max(config.ReadLimit, config.DebugResponseMaxBytes)
	}
	if config.ReadLimit < 64 {
		config.ReadLimit = 64
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
func (c *Client) runTCPClient(host, port, tokenID, sessionID string) BusinessResponse {
	if strings.TrimSpace(sessionID) == "" {
		log.Printf("❌❌ 客户端 %d: session_id不能为空", c.id)
		return BusinessResponse{}
	}

	if strings.TrimSpace(tokenID) == "" {
		log.Printf("❌❌ 客户端 %d: token_id不能为空", c.id)
		return BusinessResponse{}
	}

	// 连接服务器
	address := net.JoinHostPort(host, port)
	dialer := net.Dialer{
		Timeout:   tcpConnectTimeout(c.config),
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		log.Printf("客户端 %d Dial err: %s", c.id, err.Error())
		return BusinessResponse{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(tcpOperationTimeout(c.config)))
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
	//log.Printf("客户端 %d 使用 token_id: %s", c.id, tokenData)
	if tokenData == "" {
		log.Printf("❌❌ 客户端 %d: 没有可用的 token 信息，无法继续", c.id)
		return BusinessResponse{}
	}

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
		log.Printf("客户端 %d ApplyPreset err: %s", c.id, err.Error())
		return BusinessResponse{}
	}

	err = uconn.Handshake()
	if err != nil {
		log.Printf("客户端 %d TLS handshake err: %s", c.id, err.Error())
		return BusinessResponse{}
	}

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
	//log.Printf("客户端 %d 使用 session_id: %s", c.id, sessionIDStr)
	copy(header.SessionID[:], []byte(sessionIDStr))

	copy(header.AppName[:], appNameBytes)

	bytesRequest, err := header.Marshal()
	if err != nil {
		log.Printf("客户端 %d Marshal header error: %s", c.id, err)
		return BusinessResponse{}
	}

	_, err = uconn.Write(bytesRequest)
	if err != nil {
		log.Printf("客户端 %d Send header error: %s", c.id, err)
		return BusinessResponse{}
	}

	// 读取并解析服务器响应
	_ = uconn.SetReadDeadline(time.Now().Add(tcpOperationTimeout(c.config)))
	response := make([]byte, 4096)
	n, err := uconn.Read(response)
	if err != nil {
		log.Printf("客户端 %d Read error: %s", c.id, err)
		return BusinessResponse{}
	}

	if n < 20 {
		log.Printf("❌❌ 客户端 %d: 接收数据不足: %d 字节 (需要至少20字节)", c.id, n)
		return BusinessResponse{}
	}

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
	_, err := conn.Write(requestBytes)
	if err != nil {
		log.Printf("客户端 %d Error sending request: %s", c.id, err)
		return BusinessResponse{}
	}

	readLimit := 64
	readForAssertion := false
	if c.config != nil {
		if c.config.ReadLimit > 0 {
			readLimit = c.config.ReadLimit
		}
		readForAssertion = c.config.ReturnUpstreamBody || c.config.DebugResponse
	}
	buffer := c.getBuffer(readLimit)
	defer c.putBuffer(buffer)
	if deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = deadlineConn.SetReadDeadline(time.Now().Add(tcpOperationTimeout(c.config)))
	}
	n, err := readHTTPResponse(conn, buffer, readForAssertion)
	if err != nil && err != io.EOF {
		log.Printf("客户端 %d Error reading response: %s", c.id, err)
		return BusinessResponse{}
	}
	response := buffer[:n]
	result := parseBusinessResponse(response, c.config)
	if c.config != nil && c.config.DebugResponse {
		log.Printf("客户端 %d 收到业务响应 (%d bytes):\n%s", c.id, n, debugResponsePreview(response, c.config.DebugResponseMaxBytes))
	}
	if result.Success {
		return result
	}
	log.Printf("❌❌ 客户端 %d 业务请求失败，响应: %s", c.id, response)
	return result
}

func (c *Client) getBuffer(size int) []byte {
	if size < 64 {
		size = 64
	}
	if c.bufferPool == nil {
		return make([]byte, size)
	}
	buffer, ok := c.bufferPool.Get().([]byte)
	if !ok || cap(buffer) < size {
		return make([]byte, size)
	}
	return buffer[:size]
}

func (c *Client) putBuffer(buffer []byte) {
	if c.bufferPool == nil || buffer == nil {
		return
	}
	c.bufferPool.Put(buffer)
}

func readHTTPResponse(conn net.Conn, buffer []byte, readForAssertion bool) (int, error) {
	n, err := conn.Read(buffer)
	if err != nil || !readForAssertion {
		return n, err
	}

	total := n
	if httpResponseComplete(buffer[:total]) {
		return total, nil
	}
	for total < len(buffer) {
		if deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = deadlineConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		}
		n, err = conn.Read(buffer[total:])
		if n > 0 {
			total += n
			if httpResponseComplete(buffer[:total]) {
				return total, nil
			}
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

func httpResponseComplete(response []byte) bool {
	header, body, ok := bytes.Cut(response, []byte("\r\n\r\n"))
	if !ok {
		return false
	}
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		key, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !strings.EqualFold(strings.TrimSpace(string(key)), "Content-Length") {
			continue
		}
		contentLength, err := strconv.Atoi(strings.TrimSpace(string(value)))
		if err != nil {
			return false
		}
		return len(body) >= contentLength
	}
	return false
}

func evaluateHTTPResponse(response []byte) bool {
	return bytes.Contains(response, []byte(" 200 ")) ||
		bytes.Contains(response, []byte(" 201 ")) ||
		bytes.Contains(response, []byte(" 204 ")) ||
		bytes.HasPrefix(response, []byte("HTTP/1.1 2")) ||
		bytes.HasPrefix(response, []byte("HTTP/1.0 2"))
}

func parseBusinessResponse(response []byte, config *Config) BusinessResponse {
	result := BusinessResponse{
		Success: evaluateHTTPResponse(response),
		Bytes:   len(response),
	}
	header, body, ok := bytes.Cut(response, []byte("\r\n\r\n"))
	if !ok {
		body = response
	}
	if len(header) > 0 {
		firstLine, _, _ := bytes.Cut(header, []byte("\r\n"))
		result.StatusLine = string(firstLine)
		fields := strings.Fields(result.StatusLine)
		if len(fields) >= 2 {
			if code, err := strconv.Atoi(fields[1]); err == nil {
				result.StatusCode = code
			}
		}
	}
	if config == nil || config.ReturnUpstreamBody {
		if config != nil && config.UpstreamBodyMaxBytes > 0 && len(body) > config.UpstreamBodyMaxBytes {
			body = body[:config.UpstreamBodyMaxBytes]
		}
		result.Body = string(body)
	}
	return result
}

func debugResponsePreview(response []byte, maxBytes int) string {
	if maxBytes <= 0 || maxBytes >= len(response) {
		return string(response)
	}
	return string(response[:maxBytes])
}

func NewApp(config *Config) *App {
	app := &App{
		config: config,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				size := 4096
				if config != nil && config.ReadLimit > 0 {
					size = config.ReadLimit
				}
				if size < 64 {
					size = 64
				}
				return make([]byte, size)
			},
		},
	}
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
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, authResponse{Success: false, Error: "method not allowed"})
		return
	}

	start := time.Now()
	var request authRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	request.DevID = strings.TrimSpace(request.DevID)
	if request.Username == "" {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: "username不能为空"})
		return
	}
	if request.DevID == "" {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: "devid不能为空"})
		return
	}
	if err := validateAuthPassword(request.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, authResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}

	if !a.tryAcquire(a.authSem) {
		writeJSON(w, http.StatusTooManyRequests, authResponse{Success: false, DurationMS: elapsedMS(start), Error: "too many auth requests"})
		return
	}
	defer a.release(a.authSem)

	tokenID, err := a.runQUICAuth(request)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, authResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, authResponse{Success: true, TokenID: tokenID, DurationMS: elapsedMS(start)})
}

func (a *App) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, proxyResponse{Success: false, Error: "method not allowed"})
		return
	}

	start := time.Now()
	var request proxyRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: err.Error()})
		return
	}
	request.TokenID = strings.TrimSpace(request.TokenID)
	request.SessionID = strings.TrimSpace(request.SessionID)
	if request.TokenID == "" {
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: "token_id不能为空"})
		return
	}
	if request.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: "session_id不能为空"})
		return
	}

	if !a.tryAcquire(a.proxySem) {
		writeJSON(w, http.StatusTooManyRequests, proxyResponse{Success: false, DurationMS: elapsedMS(start), Error: "too many proxy requests"})
		return
	}
	defer a.release(a.proxySem)

	client := &Client{id: int(a.clientID.Add(1)), config: a.config, bufferPool: a.bufferPool}
	upstream := client.runTCPClient(a.config.TLSHost, a.config.TLSPort, request.TokenID, request.SessionID)
	response := proxyResponse{
		Success:            upstream.Success,
		DurationMS:         elapsedMS(start),
		UpstreamStatus:     upstream.StatusLine,
		UpstreamStatusCode: upstream.StatusCode,
		UpstreamBody:       upstream.Body,
		UpstreamBytes:      upstream.Bytes,
	}
	if !upstream.Success {
		response.Error = "proxy request failed"
		writeJSON(w, http.StatusBadGateway, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) runQUICAuth(request authRequest) (string, error) {
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
	return sendSPARequest(address, authRequest, request.DevID, a.config)
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

func sendSPARequest(address string, authRequest map[string]interface{}, devid string, config *Config) (string, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), quicDialTimeout(config))
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, tlsConfig, quicConfig)
	if err != nil {
		return "", fmt.Errorf("连接失败: %w", err)
	}
	defer conn.CloseWithError(0, "client closed")

	streamTimeout := quicStreamTimeout(config)
	streamCtx, streamCancel := context.WithTimeout(context.Background(), streamTimeout)
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
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(data)
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
	if _, err := stream.Write(headerBytes); err != nil {
		return fmt.Errorf("发送消息头失败: %w", err)
	}
	if _, err := stream.Write(bodyBytes); err != nil {
		return fmt.Errorf("发送消息体失败: %w", err)
	}
	return nil
}

func receiveSPAResponse(stream *quic.Stream, timeout time.Duration) (map[string]interface{}, error) {
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
	if header.DataLen == 0 {
		return nil, errors.New("响应体长度为0")
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

func decodeJSON(r *http.Request, dst interface{}) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("解析JSON失败: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("写入HTTP响应失败: %v", err)
	}
}

func elapsedMS(start time.Time) int64 {
	return time.Since(start).Milliseconds()
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
	}
}

// ====================== 主函数 ======================
func main() {
	if len(os.Args) > 1 && isHelpArg(os.Args[1]) {
		printUsage()
		return
	}

	// 设置并发客户端数量
	// 加载配置文件
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("❌❌❌❌ 加载配置文件失败: %v", err)
	}

	app := NewApp(config)
	log.Printf("启动HTTP服务: listen=%s quic=%s tls=%s request=%s %s",
		config.ListenAddr,
		net.JoinHostPort(config.QUICHost, config.QUICPort),
		net.JoinHostPort(config.TLSHost, config.TLSPort),
		strings.ToUpper(config.RequestMethod),
		net.JoinHostPort(config.RequestHost, config.RequestPort)+config.RequestPath,
	)
	server := newHTTPServer(config, app.routes())
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP服务启动失败: %v", err)
	}
}
