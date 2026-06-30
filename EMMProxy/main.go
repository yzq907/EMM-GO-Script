package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ====================== 常量定义 ======================
const (
	TCPConnectTimeout   = 5 * time.Second
	TCPOperationTimeout = 3 * time.Second
	tcpInitHeaderSize   = 160
)

var (
	httpStatus2xxPrefix = []byte("HTTP/1.1 2")
	httpStatus200       = []byte(" 200 ")
	httpStatus201       = []byte(" 201 ")
	httpStatus204       = []byte(" 204 ")
)

// min 辅助函数，返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Config struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	ClientCount int    `json:"client_count"`
	RunDuration int    `json:"run_duration_s"`
	// 新增字段
	ServerID    int32  `json:"server_id"`
	AppName     string `json:"app_name"`
	RequestHost string `json:"request_host"`
	RequestPort string `json:"request_port"`
	RequestPath string `json:"request_path"`
	// HTTP请求配置
	UseRawRequest  bool              `json:"use_raw_request"`
	RawRequest     string            `json:"raw_request"`
	RequestMethod  string            `json:"request_method"`
	RequestHeaders map[string]string `json:"request_headers"`
	RequestBody    string            `json:"request_body"`
	// 响应断言配置
	SuccessBodyContains   string `json:"success_body_contains"`
	MaxAssertBodyBytes    int    `json:"max_assert_body_bytes"`
	DebugResponse         bool   `json:"debug_response"`
	DebugResponseMaxBytes int    `json:"debug_response_max_bytes"`
	// 连接池配置
	EnableConnectionPool bool `json:"enable_connection_pool"`
	PoolSize             int  `json:"pool_size"`
	DisableJTL           bool `json:"disable_jtl"`
	// TLS配置
	TLSConfig    *tls.Config `json:"-"` // 不序列化到JSON
	TargetAddr   string      `json:"-"`
	RequestBytes []byte      `json:"-"`
	RequestURL   string      `json:"-"`
	AppNameBytes []byte      `json:"-"`
	ReadLimit    int         `json:"-"`
}

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

type TcpInitResponseHeader struct {
	Result     int32  `json:"result"`
	IP         string `json:"ip"`
	Port       uint16 `json:"port"`
	Reserve2   int16  `json:"reserve2"`
	Reserve3   int32  `json:"reserve3"`
	Reserve4   int32  `json:"reserve4"`
	RawDataHex string `json:"raw_data_hex,omitempty"`
	DataLength int    `json:"data_length,omitempty"`
}

// JTL测试结果结构体
type JTLResult struct {
	TimeStamp       int64  // 时间戳（毫秒）
	Elapsed         int64  // 响应时间（毫秒）
	Label           string // 测试标签
	ResponseCode    string // 响应码
	ResponseMessage string // 响应消息
	ThreadName      string // 线程名称
	DataType        string // 数据类型
	Success         bool   // 是否成功
	FailureMessage  string // 失败消息
	Bytes           int64  // 接收字节数
	SentBytes       int64  // 发送字节数
	GrpThreads      int    // 组线程数
	AllThreads      int    // 所有线程数
	URL             string // URL地址
	Latency         int64  // 延迟
	IdleTime        int64  // 空闲时间
	Connect         int64  // 连接时间
}

// JTL写入器
type JTLWriter struct {
	file        *os.File
	resultChan  chan *JTLResult
	writeMutex  sync.Mutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
	batchSize   int
	batchBuffer []*JTLResult
	dropped     int64
}

// 客户端结构体
type Client struct {
	id             int
	sessionID      string
	config         *Config    // 新增配置引用
	jtlWriter      *JTLWriter // JTL写入器
	headerBuffer   []byte
	responseBuffer []byte
	statusBuffer   []byte
}

// 客户端管理器
type ClientManager struct {
	sessionIDs   []string
	startTime    time.Time
	totalTime    time.Duration
	successCount int32
	failCount    int32
	statsMutex   sync.Mutex
}

// ====================== 工具函数 ======================
func (t *TcpInitHeader) Marshal() ([]byte, error) {
	buf := make([]byte, tcpInitHeaderSize)
	t.MarshalInto(buf)
	return buf, nil
}

func (t *TcpInitHeader) MarshalInto(buf []byte) int {
	if len(buf) < tcpInitHeaderSize {
		return 0
	}
	buf = buf[:tcpInitHeaderSize]
	for i := range buf {
		buf[i] = 0
	}
	binary.LittleEndian.PutUint32(buf[0:4], uint32(t.ServerID))
	copy(buf[4:44], t.SessionID[:])
	binary.LittleEndian.PutUint32(buf[44:48], t.UDPSynAck)
	binary.LittleEndian.PutUint32(buf[48:52], t.DataLen)
	binary.LittleEndian.PutUint32(buf[52:56], t.ProtoType)
	buf[56] = t.Version
	buf[57] = t.Reserve
	binary.LittleEndian.PutUint16(buf[58:60], t.LocalPort)
	copy(buf[60:160], t.AppName[:])
	return tcpInitHeaderSize
}

func loadCSVData(filePath string) ([]string, [][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("无法打开CSV文件: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("读取CSV失败: %w", err)
	}
	if len(records) <= 1 {
		return nil, nil, fmt.Errorf("CSV文件需要至少包含一行标题和一行数据")
	}
	normalizeCSVHeaders(records[0])
	return records[0], records[1:], nil
}

func normalizeCSVHeaders(headers []string) {
	for i, header := range headers {
		headers[i] = strings.TrimSpace(strings.TrimPrefix(header, "\ufeff"))
	}
}

func loadSessionIDs(filePath string) ([]string, error) {
	headers, records, err := loadCSVData(filePath)
	if err != nil {
		return nil, err
	}

	sessionIDColumn := -1
	for i, header := range headers {
		if header == "session_id" {
			sessionIDColumn = i
			break
		}
	}
	if sessionIDColumn < 0 {
		return nil, fmt.Errorf("CSV文件缺少 session_id 字段")
	}

	sessionIDs := make([]string, 0, len(records))
	for rowIndex, record := range records {
		if sessionIDColumn >= len(record) {
			return nil, fmt.Errorf("CSV第%d行缺少 session_id 值", rowIndex+2)
		}
		sessionID := strings.TrimSpace(record[sessionIDColumn])
		if sessionID == "" {
			continue
		}
		sessionIDs = append(sessionIDs, sessionID)
	}
	if len(sessionIDs) == 0 {
		return nil, fmt.Errorf("CSV文件没有可用的 session_id 数据")
	}
	return sessionIDs, nil
}

func loadConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("无法打开配置文件: %w", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 验证必填字段
	if config.Host == "" {
		return nil, errors.New("配置文件中host字段不能为空")
	}
	if config.Port == "" {
		return nil, errors.New("配置文件中port字段不能为空")
	}
	if config.ClientCount <= 0 {
		config.ClientCount = 1 // 设置默认值
	}
	if config.RunDuration <= 0 {
		config.RunDuration = 1 // 设置默认值1毫秒
	}

	// 新增字段的默认值
	if config.ServerID == 0 {
		config.ServerID = 8400 // 默认值
	}
	if config.AppName == "" {
		config.AppName = "com.enterprise.h5.ojscqn" // 默认值
	}
	if config.RequestHost == "" {
		config.RequestHost = "127.0.0.1" // 默认值
	}
	if config.RequestPort == "" {
		config.RequestPort = "8089" // 默认值
	}
	if config.RequestPath == "" {
		config.RequestPath = "/status" // 默认值
	}
	if config.RequestMethod == "" {
		config.RequestMethod = "GET"
	}
	config.SuccessBodyContains = strings.TrimSpace(config.SuccessBodyContains)
	if config.SuccessBodyContains != "" && config.MaxAssertBodyBytes <= 0 {
		config.MaxAssertBodyBytes = 4096
	}
	config.ReadLimit = 64
	if config.SuccessBodyContains != "" {
		config.ReadLimit = config.MaxAssertBodyBytes
		if config.ReadLimit < 64 {
			config.ReadLimit = 64
		}
	}
	if config.DebugResponseMaxBytes <= 0 {
		config.DebugResponseMaxBytes = 4096
	}
	if config.DebugResponse && config.ReadLimit < config.DebugResponseMaxBytes {
		config.ReadLimit = config.DebugResponseMaxBytes
	}
	// 连接池配置默认值
	if config.PoolSize <= 0 {
		config.PoolSize = 10 // 默认连接池大小
	}
	config.TargetAddr = net.JoinHostPort(config.Host, config.Port)
	config.RequestURL = fmt.Sprintf("https://%s:%s%s", config.RequestHost, config.RequestPort, config.RequestPath)
	config.RequestBytes, err = buildRequestBytes(&config)
	if err != nil {
		return nil, err
	}
	config.AppNameBytes = []byte(config.AppName)

	// 初始化TLS配置，只创建一次
	certPool := x509.NewCertPool()
	config.TLSConfig = &tls.Config{
		ServerName:         "10.10.27.216",
		RootCAs:            certPool,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
		SessionTicketsDisabled: false,
		// 启用TLS会话复用，减少握手开销
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
		// 性能优化配置
		MinVersion:               tls.VersionTLS12,     // 使用TLS 1.2
		MaxVersion:               tls.VersionTLS12,     // 只使用TLS 1.2
		PreferServerCipherSuites: false,                // 客户端选择加密套件
		Renegotiation:            tls.RenegotiateNever, // 禁止重协商
	}

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

func NewClientManager(clientCount int) (*ClientManager, error) {
	sessionIDs, err := loadSessionIDs("session_id.csv")
	if err != nil {
		return nil, fmt.Errorf("无法加载session文件: %w", err)
	}

	cm := &ClientManager{
		sessionIDs: sessionIDs,
		startTime:  time.Now(),
	}
	return cm, nil
}

func (c *Client) runTCPClient(address string) bool {
	// 记录开始时间
	startTime := time.Now()

	// 检查 session_id 字段
	if c.sessionID == "" {
		log.Printf("❌❌❌ 客户端 %d: session_id.csv 中 session_id 为空", c.id)
		c.recordJTLResult(startTime, time.Since(startTime), false, "session_id为空", 0, 0, 0, 0)
		return false
	}

	// 为第一个客户端添加重试机制
	var conn net.Conn
	var err error
	if c.id == 0 {
		maxRetries := 3
		for retry := 0; retry < maxRetries; retry++ {
			conn, err = net.DialTimeout("tcp", address, TCPConnectTimeout)
			if err == nil {
				break
			}
			log.Printf("客户端 %d 第 %d 次连接失败: %s", c.id, retry+1, err.Error())
			if retry < maxRetries-1 {
				time.Sleep(100 * time.Millisecond)
			}
		}
	} else {
		conn, err = net.DialTimeout("tcp", address, TCPConnectTimeout)
	}
	if err != nil {
		log.Printf("客户端 %d Dial err: %s", c.id, err.Error())
		c.recordJTLResult(startTime, time.Since(startTime), false, fmt.Sprintf("连接失败: %s", err.Error()), 0, 0, time.Since(startTime), time.Since(startTime))
		return false
	}
	defer conn.Close()

	// 记录连接建立时间
	connectTime := time.Since(startTime)

	// 创建TLS连接（使用Config中的TLS配置，复用TLS配置）
	tlsConn := tls.Client(conn, c.config.TLSConfig)
	// 执行TLS握手
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("客户端 %d TLS握手失败: %s", c.id, err.Error())
		c.recordJTLResult(startTime, time.Since(startTime), false, fmt.Sprintf("TLS握手失败: %s", err.Error()), 0, 0, connectTime, time.Since(startTime))
		return false
	}

	// 复用TcpInitHeader结构，减少内存分配
	var header TcpInitHeader
	header.ServerID = c.config.ServerID
	header.UDPSynAck = 0
	header.DataLen = 160
	header.ProtoType = 1
	header.Version = 1
	header.Reserve = 0
	header.LocalPort = 9090

	// 复制session_id
	copy(header.SessionID[:], c.sessionID)

	// 从配置文件中获取app_name
	copy(header.AppName[:], c.config.AppNameBytes)

	// 序列化头部
	if len(c.headerBuffer) < tcpInitHeaderSize {
		c.headerBuffer = make([]byte, tcpInitHeaderSize)
	}
	bytesRequest := c.headerBuffer[:tcpInitHeaderSize]
	header.MarshalInto(bytesRequest)

	_, err = tlsConn.Write(bytesRequest)
	if err != nil {
		log.Printf("客户端 %d Send header error: %s", c.id, err)
		c.recordJTLResult(startTime, time.Since(startTime), false, fmt.Sprintf("发送头部失败: %s", err.Error()), 0, len(bytesRequest), connectTime, time.Since(startTime))
		return false
	}

	// 读取并解析服务器响应
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if len(c.responseBuffer) == 0 {
		c.responseBuffer = make([]byte, 4096)
	}
	n, err := tlsConn.Read(c.responseBuffer)
	if err != nil {
		log.Printf("客户端 %d Read error: %s", c.id, err)
		c.recordJTLResult(startTime, time.Since(startTime), false, fmt.Sprintf("读取响应失败: %s", err.Error()), 0, len(bytesRequest), connectTime, time.Since(startTime))
		return false
	}

	if n < 20 {
		log.Printf("❌❌❌ 客户端 %d: 接收数据不足: %d 字节 (需要至少20字节)", c.id, n)
		c.recordJTLResult(startTime, time.Since(startTime), false, fmt.Sprintf("接收数据不足: %d字节", n), n, len(bytesRequest), connectTime, time.Since(startTime))
		return false
	}

	// 记录TCP初始化完成时间
	tcpInitTime := time.Since(startTime)

	// 发送业务请求
	success := c.sendTCPHelloWithMetrics(tlsConn, startTime, connectTime, tcpInitTime, len(bytesRequest), n)

	// 记录最终结果
	totalTime := time.Since(startTime)
	c.recordJTLResult(startTime, totalTime, success, "", n, len(bytesRequest), connectTime, totalTime)

	return success
}

// 发送业务请求（兼容旧版本）
func (c *Client) sendTCPHello(conn net.Conn) bool {
	_, err := conn.Write(c.config.RequestBytes)
	if err != nil {
		log.Printf("客户端 %d Error sending request: %s", c.id, err)
		return false
	}

	readLimit := c.config.ReadLimit
	if readLimit <= 0 {
		readLimit = 64
	}
	if len(c.statusBuffer) < readLimit {
		c.statusBuffer = make([]byte, readLimit)
	}
	n, err := readHTTPResponse(conn, c.statusBuffer[:readLimit], c.config.SuccessBodyContains != "")
	if err != nil && err != io.EOF {
		log.Printf("客户端 %d Error reading response: %s", c.id, err)
		return false
	}
	response := c.statusBuffer[:n]
	if c.config.DebugResponse {
		log.Printf("🔎 客户端 %d 收到业务响应 (%d bytes):\n%s", c.id, n, debugResponsePreview(response, c.config.DebugResponseMaxBytes))
	}
	if evaluateHTTPResponse(c.config, response) {
		return true
	}
	log.Printf("❌❌❌ 客户端 %d 业务请求失败，响应: %s", c.id, response)
	return false
}

func readHTTPResponse(conn net.Conn, buffer []byte, readForAssertion bool) (int, error) {
	n, err := conn.Read(buffer)
	if err != nil || !readForAssertion {
		return n, err
	}

	total := n
	for total < len(buffer) {
		if deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = deadlineConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		}
		n, err = conn.Read(buffer[total:])
		if n > 0 {
			total += n
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

func evaluateHTTPResponse(config *Config, response []byte) bool {
	statusOK := bytes.Contains(response, httpStatus200) ||
		bytes.Contains(response, httpStatus201) ||
		bytes.Contains(response, httpStatus204) ||
		bytes.HasPrefix(response, httpStatus2xxPrefix)
	if !statusOK {
		return false
	}

	if config.SuccessBodyContains == "" {
		return true
	}
	return bytes.Contains(response, []byte(config.SuccessBodyContains))
}

func debugResponsePreview(response []byte, maxBytes int) string {
	if maxBytes <= 0 || maxBytes >= len(response) {
		return string(response)
	}
	return fmt.Sprintf("%s...(truncated, total %d bytes)", string(response[:maxBytes]), len(response))
}

// 发送业务请求（带指标收集）
func (c *Client) sendTCPHelloWithMetrics(conn net.Conn, startTime time.Time, connectTime time.Duration, tcpInitTime time.Duration, sentBytes int, receivedBytes int) bool {
	// 直接调用原始的sendTCPHello方法
	return c.sendTCPHello(conn)
}

// 记录JTL测试结果
func (c *Client) recordJTLResult(startTime time.Time, elapsed time.Duration, success bool, failureMessage string, bytesReceived int, bytesSent int, connectTime time.Duration, latency time.Duration) {
	if c.jtlWriter == nil {
		return
	}

	// 提取响应码和消息
	responseCode := "200"
	responseMessage := "OK"
	if !success {
		responseCode = "500"
		responseMessage = "Internal Server Error"
	}

	// 计算Connect和IdleTime
	connectMs := connectTime.Milliseconds()
	latencyMs := latency.Milliseconds()
	idleTime := latencyMs - connectMs
	if idleTime < 0 {
		idleTime = 0
	}

	// 创建JTL结果
	result := &JTLResult{
		TimeStamp:       startTime.UnixMilli(),
		Elapsed:         elapsed.Milliseconds(),
		Label:           "安全网关隧道转发",
		ResponseCode:    responseCode,
		ResponseMessage: responseMessage,
		ThreadName:      fmt.Sprintf("安全网关隧道转发 %d", c.id),
		DataType:        "text",
		Success:         success,
		FailureMessage:  failureMessage,
		Bytes:           int64(bytesReceived),
		SentBytes:       int64(bytesSent),
		GrpThreads:      1,
		AllThreads:      1,
		URL:             c.config.RequestURL,
		Latency:         latency.Milliseconds(),
		IdleTime:        idleTime,
		Connect:         connectMs,
	}

	// 异步写入结果
	c.jtlWriter.WriteResult(result)
}

// ====================== 统计功能 ======================
func (cm *ClientManager) updateStats(success bool) {
	if success {
		atomic.AddInt32(&cm.successCount, 1)
	} else {
		atomic.AddInt32(&cm.failCount, 1)
	}
}

func (cm *ClientManager) getStats() (int, int, time.Duration) {
	// 移除锁，直接计算总时间，因为这是一个只读操作
	totalTime := time.Since(cm.startTime)
	success := int(atomic.LoadInt32(&cm.successCount))
	fail := int(atomic.LoadInt32(&cm.failCount))
	return success, fail, totalTime
}

// ====================== JTL写入器方法 ======================

// NewJTLWriter 创建新的JTL写入器
func NewJTLWriter(filename string, bufferSize int) (*JTLWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	// 写入CSV头部
	header := "timeStamp,elapsed,label,responseCode,responseMessage,threadName,dataType,success,failureMessage,bytes,sentBytes,grpThreads,allThreads,URL,Latency,IdleTime,Connect\n"
	if _, err := file.WriteString(header); err != nil {
		file.Close()
		return nil, err
	}

	writer := &JTLWriter{
		file:        file,
		resultChan:  make(chan *JTLResult, bufferSize),
		stopChan:    make(chan struct{}),
		batchSize:   100, // 默认批量大小
		batchBuffer: make([]*JTLResult, 0, 100),
	}

	// 启动后台写入goroutine
	writer.wg.Add(1)
	go writer.writeLoop()

	return writer, nil
}

// WriteResult 异步写入测试结果
func (w *JTLWriter) WriteResult(result *JTLResult) {
	select {
	case w.resultChan <- result:
		// 成功发送到channel
	default:
		// channel已满，直接丢弃结果以避免阻塞；只低频打印，避免日志成为压测瓶颈。
		dropped := atomic.AddInt64(&w.dropped, 1)
		if dropped == 1 || dropped%10000 == 0 {
			log.Printf("⚠️ JTL写入器channel已满，已丢弃 %d 条测试结果", dropped)
		}
	}
}

// writeLoop 后台写入循环
func (w *JTLWriter) writeLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case result := <-w.resultChan:
			w.batchBuffer = append(w.batchBuffer, result)
			if len(w.batchBuffer) >= w.batchSize {
				w.flushBuffer()
			}
		case <-ticker.C:
			if len(w.batchBuffer) > 0 {
				w.flushBuffer()
			}
		case <-w.stopChan:
			for {
				select {
				case result := <-w.resultChan:
					w.batchBuffer = append(w.batchBuffer, result)
					if len(w.batchBuffer) >= w.batchSize {
						w.flushBuffer()
					}
				default:
					if len(w.batchBuffer) > 0 {
						w.flushBuffer()
					}
					if dropped := atomic.LoadInt64(&w.dropped); dropped > 0 {
						log.Printf("⚠️ JTL写入器共丢弃 %d 条测试结果", dropped)
					}
					return
				}
			}
		}
	}
}

// flushBuffer 将缓冲区的数据写入文件
func (w *JTLWriter) flushBuffer() {
	w.writeMutex.Lock()
	defer w.writeMutex.Unlock()

	if len(w.batchBuffer) == 0 {
		return
	}

	var buf strings.Builder
	buf.Grow(len(w.batchBuffer) * 180)
	for _, result := range w.batchBuffer {
		// 将结果转换为CSV行
		successStr := "true"
		if !result.Success {
			successStr = "false"
		}

		fmt.Fprintf(&buf, "%d,%d,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%s,%d,%d,%d\n",
			result.TimeStamp,
			result.Elapsed,
			escapeCSV(result.Label),
			result.ResponseCode,
			escapeCSV(result.ResponseMessage),
			escapeCSV(result.ThreadName),
			result.DataType,
			successStr,
			escapeCSV(result.FailureMessage),
			result.Bytes,
			result.SentBytes,
			result.GrpThreads,
			result.AllThreads,
			escapeCSV(result.URL),
			result.Latency,
			result.IdleTime,
			result.Connect,
		)
	}

	// 写入文件
	if _, err := w.file.WriteString(buf.String()); err != nil {
		log.Printf("❌ 写入JTL文件失败: %v", err)
	}

	// 清空缓冲区
	w.batchBuffer = w.batchBuffer[:0]
}

// Close 关闭JTL写入器
func (w *JTLWriter) Close() {
	close(w.stopChan)
	w.wg.Wait()

	w.writeMutex.Lock()
	defer w.writeMutex.Unlock()

	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
}

// escapeCSV 转义CSV字段中的特殊字符
func escapeCSV(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// ====================== 主函数 ======================
func main() {
	// 设置并发客户端数量
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("❌❌❌ 加载配置文件失败: %v", err)
	}

	// 使用配置值替换硬编码值
	clientCount := config.ClientCount
	runDuration := time.Duration(config.RunDuration) * time.Second

	// 创建客户端管理器
	cm, err := NewClientManager(0)
	if err != nil {
		log.Fatalf("❌❌❌ 创建客户端管理器失败: %v", err)
	}

	log.Printf("🚀🚀🚀 启动 %d 个并行客户端，运行时间: %v", clientCount, runDuration)

	// 创建JTL写入器
	var jtlWriter *JTLWriter
	if config.DisableJTL {
		log.Printf("📝 已禁用JTL文件写入")
	} else {
		jtlWriter, err = NewJTLWriter("test_results.jtl", clientCount*100)
		if err != nil {
			log.Printf("⚠️ 创建JTL写入器失败: %v，将继续运行但不记录JTL文件", err)
			jtlWriter = nil
		} else {
			defer jtlWriter.Close()
			log.Printf("📝 JTL文件将保存到: test_results.jtl")
		}
	}

	// 设置运行截止时间
	endTime := time.Now().Add(runDuration)

	// 使用工作池模式管理goroutine
	type Task struct {
		sessIdx int
		id      int
	}

	// 创建任务通道和工作池
	taskChan := make(chan Task, clientCount*2) // 任务缓冲队列
	var wg sync.WaitGroup

	// 启动工作goroutine
	for i := 0; i < clientCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			client := &Client{
				config:         config,
				jtlWriter:      jtlWriter,
				headerBuffer:   make([]byte, tcpInitHeaderSize),
				responseBuffer: make([]byte, 4096),
				statusBuffer:   make([]byte, 64),
			}
			for task := range taskChan {
				client.id = task.id
				client.sessionID = cm.sessionIDs[task.sessIdx]
				success := client.runTCPClient(config.TargetAddr)

				// 更新统计信息
				cm.updateStats(success)
				// 只在失败时打印日志，减少高频调用时的日志开销
				if !success {
					log.Printf("❌ 客户端 %d 执行失败", task.id)
				}
			}
		}(i)
	}

	// 用于循环使用数据行的索引
	sessionIndex := 0
	clientID := 0

	// 在主循环中持续发送任务
	for time.Now().Before(endTime) {
		taskChan <- Task{
			sessIdx: sessionIndex,
			id:      clientID,
		}

		// 更新索引，循环使用数据行
		sessionIndex = (sessionIndex + 1) % len(cm.sessionIDs)
		clientID++
	}

	// 关闭任务通道，通知工作goroutine结束
	close(taskChan)

	// 等待所有工作goroutine完成
	wg.Wait()

	// 获取最终统计信息
	successCount, failCount, totalTime := cm.getStats()
	var tps float64
	if totalTime.Seconds() > 0 {
		tps = float64(successCount) / totalTime.Seconds()
	}

	// 打印详细统计报告
	log.Printf("🎊🎊🎊 运行完成! 总运行时间: %v", runDuration)
	log.Printf("📊📊📊 ========== 统计报告 ==========")
	log.Printf("📊📊📊 实际运行时间: %v", totalTime)
	log.Printf("📊📊📊 成功次数: %d", successCount)
	log.Printf("📊📊📊 失败次数: %d", failCount)
	totalRequests := successCount + failCount
	if totalRequests > 0 {
		log.Printf("📊📊📊 成功率: %.2f%%", float64(successCount)/float64(totalRequests)*100)
	} else {
		log.Printf("📊📊📊成功率: 0.00%%")
	}
	totalTPS := 0.0
	if totalTime.Seconds() > 0 {
		totalTPS = float64(totalRequests) / totalTime.Seconds()
	}
	log.Printf("📊📊📊 成功TPS: %.2f", tps)
	log.Printf("📊📊📊 总TPS: %.2f", totalTPS)
	log.Printf("📊📊📊 ==============================")
}
