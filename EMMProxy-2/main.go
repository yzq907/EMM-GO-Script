package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gmtls "github.com/tjfoc/gmsm/gmtls"
	"github.com/tjfoc/gmsm/x509"
)

// ====================== 常量定义 ======================
const (
	TCPConnectTimeout   = 5 * time.Second
	TCPOperationTimeout = 3 * time.Second
)

// min 辅助函数，返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Config struct {
	Host         string        `json:"host"`
	Port         string        `json:"port"`
	ClientCount  int           `json:"client_count"`
	RunCount     int           `json:"run_count"`
	Timeout      time.Duration `json:"timeout_s"`
	ServerID     int32         `json:"server_id"`
	AppName      string        `json:"app_name"`
	HttpRequest  string        `json:"http_request"`  // 单个HTTP请求模板（兼容旧配置）
	HttpRequests []string      `json:"http_requests"` // 多个HTTP请求模板（新配置）
	TestMode     string        `json:"test_mode"`
	SavePath     string        `json:"save_path"`
	LogFilePath  string        `json:"log_file_path"`
	TLSConfig    *gmtls.Config `json:"-"`
}

// ====================== 结构体定义 ======================

// TCP初始化头结构
type TcpInitHeader struct {
	ServerID  int32
	SessionID [40]byte
	UDPSynAck uint32
	DataLen   uint32
	ProtoType uint32
	Version   uint8
	Reserve   uint8
	LocalPort uint16
	AppName   [100]byte
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

// 客户端结构体
type Client struct {
	id         int
	sessionMap map[string]string
	config     *Config
	manager    *ClientManager
}

// 客户端管理器
type ClientManager struct {
	sessionHeaders  []string
	sessionData     [][]string
	startTime       time.Time
	totalTime       time.Duration
	successCount    int32
	failCount       int32
	statsMutex      sync.Mutex
	logFile         *os.File
	logMutex        sync.Mutex
	requestIndex    int
	requestIndexMux sync.Mutex
}

// ====================== 工具函数 ======================
func (t *TcpInitHeader) Marshal() ([]byte, error) {
	// 预先分配精确大小的buffer，避免扩容 (4+40+4+4+4+1+1+2+100=160字节)
	buf := bytes.NewBuffer(make([]byte, 0, 160))
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
	return records[0], records[1:], nil
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
	if config.RunCount <= 0 {
		config.RunCount = 1 // 设置默认值1次
	}

	// 新增字段的默认值
	if config.ServerID == 0 {
		config.ServerID = 8400 // 默认值
	}
	if config.AppName == "" {
		config.AppName = "com.enterprise.h5.ojscqn"
	}

	if len(config.HttpRequests) == 0 {
		if config.HttpRequest == "" {
			config.HttpRequests = []string{
				"GET /download/test_20m.bin HTTP/1.1\r\n" +
					"Host: 10.10.27.171:8089\r\n" +
					"Connection: close\r\n" +
					"\r\n",
			}
		} else {
			config.HttpRequests = []string{config.HttpRequest}
		}
	}
	if config.Timeout <= 0 {
		config.Timeout = 60 * time.Second // 默认60秒超时
	} else {
		// 将配置文件中的秒数转换为time.Duration
		config.Timeout = config.Timeout * time.Second
	}
	if config.TestMode == "" {
		config.TestMode = "memory" // 默认写入内存模式
	}
	if config.SavePath == "" {
		config.SavePath = "./downloads" // 默认保存路径
	}

	// 初始化TLS配置，只创建一次
	certPool := x509.NewCertPool()
	config.TLSConfig = &gmtls.Config{
		GMSupport:          &gmtls.GMSupport{},
		ServerName:         "10.10.27.216",
		RootCAs:            certPool,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			gmtls.GMTLS_SM2_WITH_SM4_SM3,
			gmtls.GMTLS_ECDHE_SM2_WITH_SM4_SM3,
		},
		SessionTicketsDisabled: false,
		// 启用TLS会话复用，减少握手开销
		ClientSessionCache: gmtls.NewLRUClientSessionCache(1024),
	}

	return &config, nil
}

func NewClientManager(clientCount int, config *Config) (*ClientManager, error) {
	sessionHeaders, sessionData, err := loadCSVData("session_id.csv")
	if err != nil {
		return nil, fmt.Errorf("无法加载session文件: %w", err)
	}

	cm := &ClientManager{
		sessionHeaders: sessionHeaders,
		sessionData:    sessionData,
		startTime:      time.Now(),
	}

	// 初始化日志文件
	if config.LogFilePath != "" {
		if err := cm.initLogFile(config.LogFilePath); err != nil {
			log.Printf("⚠️⚠️ 初始化日志文件失败: %v", err)
		}
	}

	return cm, nil
}

// 初始化日志文件
func (cm *ClientManager) initLogFile(logPath string) error {
	// 确保日志目录存在
	sepIndex := strings.LastIndex(logPath, string(os.PathSeparator))
	if sepIndex > 0 {
		logDir := logPath[:sepIndex]
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("创建日志目录失败: %w", err)
		}
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	cm.logFile = file
	cm.writeLog("========== 下载测试开始 ==========")
	cm.writeLog(fmt.Sprintf("开始时间: %s", time.Now().Format("2006-01-02 15:04:05")))

	return nil
}

// 写入日志文件
func (cm *ClientManager) writeLog(message string) {
	if cm.logFile == nil {
		return
	}

	cm.logMutex.Lock()
	defer cm.logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, message)
	if _, err := cm.logFile.WriteString(logLine); err != nil {
		log.Printf("写入日志文件失败: %v", err)
	}
}

// 只写入日志文件，不打印到终端
func (cm *ClientManager) writeLogOnly(message string) {
	if cm.logFile == nil {
		return
	}

	cm.logMutex.Lock()
	defer cm.logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logLine := fmt.Sprintf("[%s] %s\n", timestamp, message)
	cm.logFile.WriteString(logLine)
}

// 关闭日志文件
func (cm *ClientManager) closeLogFile() {
	if cm.logFile != nil {
		cm.writeLog("========== 下载测试结束 ==========")
		cm.logFile.Close()
	}
}

func (c *Client) runTCPClient(host, port string) bool {
	// 检查 session_id 字段
	if _, ok := c.sessionMap["session_id"]; !ok {
		log.Printf("❌❌❌ 客户端 %d: session_id.csv 中缺少 session_id 字段", c.id)
		return false
	}

	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, TCPConnectTimeout)
	if err != nil {
		log.Printf("客户端 %d Dial err: %s", c.id, err.Error())
		return false
	}
	defer conn.Close()

	// 记录连接信息
	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()
	c.manager.writeLog(fmt.Sprintf("客户端 %d 连接建立 - 本地: %s, 远程: %s", c.id, localAddr, remoteAddr))

	// 创建国密TLS连接（使用Config中的TLS配置，复用TLS配置）
	tlsConn := gmtls.Client(conn, c.config.TLSConfig)
	// 执行国密TLS握手
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("客户端 %d TLS握手失败: %s", c.id, err.Error())
		return false
	}

	c.manager.writeLog(fmt.Sprintf("客户端 %d TLS握手成功", c.id))

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
	sessionIDStr := c.sessionMap["session_id"]
	sessionIDBytes := []byte(sessionIDStr)
	copy(header.SessionID[:], sessionIDBytes[:min(len(sessionIDBytes), len(header.SessionID))])

	// 从配置文件中获取app_name
	appName := c.config.AppName
	appNameBytes := []byte(appName)
	copy(header.AppName[:], appNameBytes[:min(len(appNameBytes), len(header.AppName))])

	// 序列化头部
	bytesRequest, err := header.Marshal()
	if err != nil {
		log.Printf("客户端 %d Marshal header error: %s", c.id, err)
		return false
	}

	_, err = tlsConn.Write(bytesRequest)
	if err != nil {
		log.Printf("客户端 %d Send header error: %s", c.id, err)
		return false
	}

	// 读取并解析服务器响应
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		log.Printf("客户端 %d Read error: %s", c.id, err)
		return false
	}

	if n < 20 {
		log.Printf("❌❌❌ 客户端 %d: 接收数据不足: %d 字节 (需要至少20字节)", c.id, n)
		return false
	}
	c.sendTCPHello(tlsConn)
	return true
}

// 发送业务请求，下载文件
func (c *Client) sendTCPHello(conn net.Conn) bool {
	c.manager.requestIndexMux.Lock()
	requestIndex := c.manager.requestIndex
	c.manager.requestIndex = (c.manager.requestIndex + 1) % len(c.config.HttpRequests)
	c.manager.requestIndexMux.Unlock()

	request := c.config.HttpRequests[requestIndex]

	_, err := conn.Write([]byte(request))
	if err != nil {
		errMsg := fmt.Sprintf("客户端 %d 发送下载请求失败: %v", c.id, err)
		log.Print(errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		return false
	}

	c.manager.writeLog(fmt.Sprintf("客户端 %d 发送下载请求成功 (请求索引: %d/%d)", c.id, requestIndex, len(c.config.HttpRequests)))

	// 设置读取超时，适应大文件下载
	conn.SetReadDeadline(time.Now().Add(c.config.Timeout))

	// 读取响应头
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		errMsg := fmt.Sprintf("客户端 %d 读取响应头失败: %v", c.id, err)
		log.Print(errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		return false
	}

	// 检查是否包含"200"或"206"状态码
	statusCode := ""
	if bytes.Contains(buffer[:n], []byte(" 200 ")) {
		statusCode = "200"
	} else if bytes.Contains(buffer[:n], []byte(" 206 ")) {
		statusCode = "206"
	} else {
		errMsg := fmt.Sprintf("客户端 %d 下载请求失败，状态码不是200或206", c.id)
		log.Printf("❌❌❌ %s", errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		c.manager.writeLog(fmt.Sprintf("客户端 %d 响应内容: %s", c.id, string(buffer[:min(n, 200)])))
		return false
	}

	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 响应状态码: %s", c.id, statusCode))

	logLen := min(n, 500)
	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 响应头内容: %s", c.id, string(buffer[:logLen])))

	// 找到响应头结束位置（\r\n\r\n）
	headerEnd := bytes.Index(buffer[:n], []byte("\r\n\r\n"))
	if headerEnd == -1 {
		errMsg := fmt.Sprintf("客户端 %d 无法解析响应头", c.id)
		log.Printf("❌❌❌ %s", errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		return false
	}

	// 解析 Content-Length 和 Content-Range
	expectedLength := -1
	contentLengthPrefix := "Content-Length: "
	contentRangePrefix := "Content-Range: "

	if idx := bytes.Index(buffer[:headerEnd], []byte(contentLengthPrefix)); idx != -1 {
		start := idx + len(contentLengthPrefix)
		end := bytes.Index(buffer[start:headerEnd], []byte("\r\n"))
		if end != -1 {
			lengthStr := string(buffer[start : start+end])
			fmt.Sscanf(lengthStr, "%d", &expectedLength)
			c.manager.writeLogOnly(fmt.Sprintf("客户端 %d Content-Length: %d 字节", c.id, expectedLength))
		}
	}

	// 对于206响应，解析Content-Range获取总文件大小
	if statusCode == "206" {
		c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 检测到206响应，开始解析Content-Range", c.id))
		if idx := bytes.Index(buffer[:headerEnd], []byte(contentRangePrefix)); idx != -1 {
			//c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 找到Content-Range头，位置: %d", c.id, idx))
			start := idx + len(contentRangePrefix)
			// 在Content-Range头之后查找\r\n，而不是在整个headerEnd范围内
			endPos := bytes.Index(buffer[start:], []byte("\r\n"))
			if endPos != -1 {
				// 调整endPos为相对于buffer的绝对位置
				end := start + endPos
				//c.manager.writeLogOnly(fmt.Sprintf("客户端 %d Content-Range头范围: start=%d, end=%d", c.id, start, end))
				rangeStr := string(buffer[start:end])
				c.manager.writeLogOnly(fmt.Sprintf("客户端 %d Content-Range原始值: %s", c.id, rangeStr))

				// 更健壮的解析逻辑
				rangeStr = strings.TrimSpace(rangeStr)

				// 移除可能的"bytes "前缀
				if strings.HasPrefix(rangeStr, "bytes ") {
					rangeStr = strings.TrimPrefix(rangeStr, "bytes ")
				}

				// 分割格式: "0-1023/20971520"
				parts := strings.Split(rangeStr, "/")
				if len(parts) >= 2 {
					rangePart := strings.TrimSpace(parts[0])
					rangeParts := strings.Split(rangePart, "-")

					if len(rangeParts) == 2 {
						startByte, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
						endByte, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
						totalSize, err3 := strconv.Atoi(strings.TrimSpace(parts[1]))

						if err1 == nil && err2 == nil && err3 == nil {
							c.manager.writeLogOnly(fmt.Sprintf("客户端 %d Content-Range: bytes %d-%d/%d (分片下载)", c.id, startByte, endByte, totalSize))
							// 对于分片下载，expectedLength应该是本次返回的大小
							expectedLength = endByte - startByte + 1
						} else {
							c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d Content-Range解析失败: startByte=%v, endByte=%v, totalSize=%v", c.id, err1, err2, err3))
							// 如果解析失败，使用Content-Length
						}
					} else {
						c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d Content-Range格式错误: rangeParts=%v", c.id, rangeParts))
					}
				} else {
					c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d Content-Range格式错误: parts=%v", c.id, parts))
				}
			}
		} else {
			c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 未找到Content-Range头", c.id))
		}
	}

	// 提取响应头后的第一个数据块
	bodyStart := headerEnd + 4
	fileData := buffer[bodyStart:n]

	var totalBytes int

	// 根据配置模式选择下载方式
	if c.config.TestMode == "disk" {
		// 写入磁盘模式
		totalBytes = c.downloadToDisk(conn, fileData, expectedLength)
	} else {
		// 写入内存模式（默认）
		totalBytes = c.downloadToMemory(conn, fileData, expectedLength)
	}

	if totalBytes > 0 {
		if expectedLength > 0 {
			if totalBytes == expectedLength {
				successMsg := fmt.Sprintf("客户端 %d 文件下载成功，总大小: %d 字节 (匹配期望值)", c.id, totalBytes)
				log.Printf("✅✅ %s", successMsg)
				c.manager.writeLog(fmt.Sprintf("✅ %s", successMsg))
			} else {
				warnMsg := fmt.Sprintf("客户端 %d 文件下载完成，总大小: %d 字节 (期望: %d 字节，差异: %d 字节)",
					c.id, totalBytes, expectedLength, totalBytes-expectedLength)
				log.Printf("⚠️⚠️ %s", warnMsg)
				c.manager.writeLog(fmt.Sprintf("⚠️ %s", warnMsg))
				c.manager.writeLog(fmt.Sprintf("⚠️ 客户端 %d 下载不完整，可能原因: 服务器提前关闭连接或网络传输中断", c.id))
			}
		} else {
			successMsg := fmt.Sprintf("客户端 %d 文件下载成功，总大小: %d 字节", c.id, totalBytes)
			log.Printf("✅✅ %s", successMsg)
			c.manager.writeLog(fmt.Sprintf("✅ %s", successMsg))
		}
		return true
	} else {
		errMsg := fmt.Sprintf("客户端 %d 文件下载失败，未下载到任何数据", c.id)
		log.Printf("❌❌❌ %s", errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
	}
	return false
}

// 检查连接状态
func (c *Client) checkConnectionState(conn net.Conn, totalBytes, expectedLength, totalFileSize int) {
	// 尝试读取连接状态
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	testBuf := make([]byte, 1)
	n, err := conn.Read(testBuf)

	if err == io.EOF {
		c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 连接状态: 已关闭 (EOF)", c.id))
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 连接状态: 超时 (可能连接已关闭)", c.id))
	} else if err != nil {
		c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 连接状态: 错误 - %v", c.id, err))
	} else if n > 0 {
		c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 连接状态: 仍有数据可读 (%d 字节)，可能数据未完全接收", c.id, n))
	} else {
		c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 连接状态: 正常", c.id))
	}

	// 检查是否达到期望大小
	if expectedLength > 0 {
		if totalBytes < expectedLength {
			missing := expectedLength - totalBytes
			c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 缺失 %d 字节 (%.2f%%)", c.id, missing, float64(missing)/float64(expectedLength)*100))
		} else if totalBytes > expectedLength {
			extra := totalBytes - expectedLength
			c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 多读取 %d 字节 (%.2f%%)", c.id, extra, float64(extra)/float64(expectedLength)*100))
		}
	}

	// 对于分片下载，显示总文件大小信息
	if totalFileSize > 0 && totalFileSize != expectedLength {
		c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 分片下载信息: 本次下载 %d 字节，文件总大小 %d 字节", c.id, totalBytes, totalFileSize))
	}
}

// 写入内存模式：只统计字节数，不保存数据
func (c *Client) downloadToMemory(conn net.Conn, firstChunk []byte, expectedLength int) int {
	buffer := make([]byte, 4096)
	totalBytes := len(firstChunk)
	readCount := 0
	lastReadSize := 0
	zeroCount := 0

	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 开始下载到内存，初始数据块: %d 字节", c.id, totalBytes))

	if expectedLength > 0 && totalBytes >= expectedLength {
		c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 初始数据块已达到期望大小 %d 字节，无需继续读取", c.id, expectedLength))
		return totalBytes
	}

	for {
		n, err := conn.Read(buffer)
		readCount++

		if err != nil {
			if err == io.EOF {
				c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 读取完成（EOF），共读取 %d 次，总大小: %d 字节", c.id, readCount, totalBytes))
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				errMsg := fmt.Sprintf("客户端 %d 读取超时，已读取 %d 字节，共读取 %d 次", c.id, totalBytes, readCount)
				log.Printf("⚠️ %s", errMsg)
				c.manager.writeLog(fmt.Sprintf("⚠️ %s", errMsg))
				return totalBytes
			}
			errMsg := fmt.Sprintf("客户端 %d 读取数据失败: %v", c.id, err)
			log.Print(errMsg)
			c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
			return 0
		}

		if n == 0 {
			zeroCount++
			c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 读取到空数据（n=0），第 %d 次出现，共读取 %d 次，总大小: %d 字节", c.id, zeroCount, readCount, totalBytes))

			// 如果连续多次读到空数据，说明连接已关闭
			if zeroCount >= 3 {
				c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 连续 %d 次读到空数据，连接可能已关闭", c.id, zeroCount))
				break
			}

			// 短暂等待后继续尝试
			time.Sleep(10 * time.Millisecond)
			continue
		} else {
			zeroCount = 0
		}

		totalBytes += n
		lastReadSize = n

		// 每100次读取记录一次进度
		if readCount%100 == 0 {
			c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 下载进度: 已读取 %d 次，当前大小: %d 字节", c.id, readCount, totalBytes))
		}

		// 如果已经达到期望大小，停止读取
		if expectedLength > 0 && totalBytes >= expectedLength {
			c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 已达到期望大小 %d 字节，停止读取", c.id, expectedLength))
			break
		}
	}

	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 下载结束，最后一次读取: %d 字节，共读取 %d 次，总大小: %d 字节", c.id, lastReadSize, readCount, totalBytes))
	return totalBytes
}

// 写入磁盘模式：将数据保存到文件
func (c *Client) downloadToDisk(conn net.Conn, firstChunk []byte, expectedLength int) int {
	// 确保保存目录存在
	if err := os.MkdirAll(c.config.SavePath, 0755); err != nil {
		errMsg := fmt.Sprintf("客户端 %d 创建目录失败: %v", c.id, err)
		log.Print(errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		return 0
	}

	// 生成文件名：client_<id>_<timestamp>.bin
	fileName := fmt.Sprintf("download_client_%d_%d.bin", c.id, time.Now().UnixNano())

	// 构建完整文件路径
	filePath := fmt.Sprintf("%s%c%s", c.config.SavePath, os.PathSeparator, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		errMsg := fmt.Sprintf("客户端 %d 创建文件失败: %v", c.id, err)
		log.Print(errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		return 0
	}
	defer file.Close()

	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 开始下载到磁盘，文件路径: %s", c.id, filePath))

	// 写入第一个数据块
	_, err = file.Write(firstChunk)
	if err != nil {
		errMsg := fmt.Sprintf("客户端 %d 写入文件失败: %v", c.id, err)
		log.Print(errMsg)
		c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
		return 0
	}
	totalBytes := len(firstChunk)

	if expectedLength > 0 && totalBytes >= expectedLength {
		c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 初始数据块已达到期望大小 %d 字节，无需继续读取", c.id, expectedLength))
		return totalBytes
	}

	// 读取并写入剩余数据
	buffer := make([]byte, 4096)
	readCount := 0
	lastReadSize := 0
	zeroCount := 0
	for {
		n, err := conn.Read(buffer)
		readCount++

		if err != nil {
			if err == io.EOF {
				c.manager.writeLog(fmt.Sprintf("客户端 %d 读取完成（EOF），共读取 %d 次，总大小: %d 字节", c.id, readCount, totalBytes))
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				errMsg := fmt.Sprintf("客户端 %d 读取超时，已读取 %d 字节，共读取 %d 次", c.id, totalBytes, readCount)
				log.Printf("⚠️ %s", errMsg)
				c.manager.writeLog(fmt.Sprintf("⚠️ %s", errMsg))
				return totalBytes
			}
			errMsg := fmt.Sprintf("客户端 %d 读取数据失败: %v", c.id, err)
			log.Print(errMsg)
			c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
			return 0
		}

		if n == 0 {
			zeroCount++
			c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 读取到空数据（n=0），第 %d 次出现，共读取 %d 次，总大小: %d 字节", c.id, zeroCount, readCount, totalBytes))

			// 如果连续多次读到空数据，说明连接已关闭
			if zeroCount >= 3 {
				c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 连续 %d 次读到空数据，连接可能已关闭", c.id, zeroCount))
				break
			}

			// 短暂等待后继续尝试
			time.Sleep(10 * time.Millisecond)
			continue
		} else {
			zeroCount = 0
		}

		_, err = file.Write(buffer[:n])
		if err != nil {
			errMsg := fmt.Sprintf("客户端 %d 写入文件失败: %v", c.id, err)
			log.Print(errMsg)
			c.manager.writeLog(fmt.Sprintf("❌ %s", errMsg))
			return 0
		}
		totalBytes += n
		lastReadSize = n

		// 每100次读取记录一次进度
		if readCount%100 == 0 {
			c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 下载进度: 已读取 %d 次，当前大小: %d 字节", c.id, readCount, totalBytes))
		}

		// 如果已经达到期望大小，停止读取
		if expectedLength > 0 && totalBytes >= expectedLength {
			c.manager.writeLogOnly(fmt.Sprintf("⚠️ 客户端 %d 已达到期望大小 %d 字节，停止读取", c.id, expectedLength))
			break
		}
	}

	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 下载结束，最后一次读取: %d 字节，共读取 %d 次，总大小: %d 字节", c.id, lastReadSize, readCount, totalBytes))
	c.manager.writeLogOnly(fmt.Sprintf("客户端 %d 文件已保存到: %s", c.id, filePath))
	return totalBytes
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
	totalTime := time.Since(cm.startTime)
	success := int(atomic.LoadInt32(&cm.successCount))
	fail := int(atomic.LoadInt32(&cm.failCount))
	return success, fail, totalTime
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
	runCount := config.RunCount // 运行次数
	host := config.Host
	port := config.Port

	// 创建客户端管理器
	cm, err := NewClientManager(0, config)
	if err != nil {
		log.Fatalf("❌❌❌ 创建客户端管理器失败: %v", err)
	}
	defer cm.closeLogFile()

	log.Printf("🚀🚀🚀 启动 %d 个并行客户端，每客户端运行次数: %d，总请求数: %d", clientCount, runCount, clientCount*runCount)

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
			for task := range taskChan {
				// 动态创建session映射
				sessionMap := make(map[string]string)
				for j, header := range cm.sessionHeaders {
					if j < len(cm.sessionData[task.sessIdx]) {
						sessionMap[header] = strings.TrimSpace(cm.sessionData[task.sessIdx][j])
					}
				}
				// 创建新的客户端实例
				client := &Client{
					id:         task.id,
					sessionMap: sessionMap,
					config:     config,
					manager:    cm,
				}
				success := client.runTCPClient(host, port)

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

	// 在主循环中发送指定次数的任务，总任务数为：客户端数量 * 运行次数
	totalTasks := clientCount * runCount
	for i := 0; i < totalTasks; i++ {
		taskChan <- Task{
			sessIdx: sessionIndex,
			id:      clientID,
		}
		// 更新索引，循环使用数据行
		sessionIndex = (sessionIndex + 1) % len(cm.sessionData)
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
	totalRequests := successCount + failCount
	log.Printf("🎊🎊🎊 运行完成! 总运行次数: %d", totalRequests)
	log.Printf("📊📊📊 ========== 统计报告 ==========")
	log.Printf("📊📊📊 实际运行时间: %v", totalTime)
	log.Printf("📊📊📊 成功次数: %d", successCount)
	log.Printf("📊📊📊 失败次数: %d", failCount)
	if totalRequests > 0 {
		log.Printf("📊📊📊 成功率: %.2f%%", float64(successCount)/float64(totalRequests)*100)
	} else {
		log.Printf("📊📊📊成功率: 0.00%%")
	}
	if totalTime.Seconds() > 0 {
		log.Printf("📊📊📊 TPS: %.2f (每秒处理事务数)", tps)
	}
	log.Printf("📊📊📊 ==============================")
}
