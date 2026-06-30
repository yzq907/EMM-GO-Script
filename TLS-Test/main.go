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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ====================== 常量定义 ======================
const (
	AUTH_REQUEST  = 1002
	AUTH_RESPONSE = 1003
	HEARTBEAT     = 1004
	JSON          = 1
	PROTOBUF      = 2
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

type TcpInitResponseHeader struct {
	Result   int32  `json:"result"`   // 初始化结果
	IP       string `json:"ip"`       // 网关IP（转换为字符串）
	Port     uint16 `json:"port"`     // 网关端口
	Reserve2 int16  `json:"reserve2"` // 保留字节
	Reserve3 int32  `json:"reserve3"` // 保留字节
	Reserve4 int32  `json:"reserve4"` // 保留字节
}

// 客户端结构体
type Client struct {
	id         int
	tokenInfo  string
	tokenLock  sync.Mutex
	sessionMap map[string]string
	tokenMap   map[string]string
	success    bool // 添加：标记客户端是否成功
}

// 客户端管理器
type ClientManager struct {
	mu             sync.Mutex
	sessionHeaders []string
	sessionData    [][]string
	tokenHeaders   []string
	tokenData      [][]string
	startTime      time.Time
	totalTime      time.Duration
	successCount   int32
	failCount      int32
	statsMutex     sync.Mutex
}

type Config struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	ClientCount int    `json:"client_count"`
	RunDuration int    `json:"run_duration_s"`
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

// 加载CSV数据
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
	if config.RunDuration <= 0 {
		config.RunDuration = 1 // 设置默认值1毫秒
	}

	return &config, nil
}

// 创建客户端管理器
func NewClientManager(clientCount int) (*ClientManager, error) {
	// 加载session数据
	sessionHeaders, sessionData, err := loadCSVData("session_id.csv")
	if err != nil {
		return nil, fmt.Errorf("无法加载session文件: %w", err)
	}

	// 加载token数据
	tokenHeaders, tokenData, err := loadCSVData("token_client.csv")
	if err != nil {
		return nil, fmt.Errorf("无法加载token文件: %w", err)
	}

	cm := &ClientManager{
		sessionHeaders: sessionHeaders,
		sessionData:    sessionData,
		tokenHeaders:   tokenHeaders,
		tokenData:      tokenData,
		startTime:      time.Now(),
	}
	return cm, nil
}

// ====================== TCP 客户端功能 ======================
func (c *Client) runTCPClient(host, port string) bool {
	// 检查 session_id 字段
	if _, ok := c.sessionMap["session_id"]; !ok {
		log.Printf("❌❌ 客户端 %d: session_id.csv 中缺少 session_id 字段", c.id)
		return false
	}

	if _, ok := c.tokenMap["token_id"]; !ok {
		log.Printf("❌❌ 客户端 %d: token_client.csv 中缺少 token_id 字段", c.id)
		return false
	}

	// 连接服务器
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, TCPConnectTimeout)
	if err != nil {
		log.Printf("客户端 %d Dial err: %s", c.id, err.Error())
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(TCPOperationTimeout))
	// 创建 utls config
	config := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "10.10.27.126",
	}

	tokenData := c.tokenMap["token_id"]
	//log.Printf("客户端 %d 使用 token_id: %s", c.id, tokenData)
	if tokenData == "" {
		log.Printf("❌❌ 客户端 %d: 没有可用的 token 信息，无法继续", c.id)
		return false
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
			&utls.SNIExtension{ServerName: "10.10.27.126"},
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
		return false
	}

	err = uconn.Handshake()
	if err != nil {
		log.Printf("客户端 %d TLS handshake err: %s", c.id, err.Error())
		return false
	}

	// 创建并填充头结构
	header := TcpInitHeader{
		ServerID:  9,
		UDPSynAck: 0,
		DataLen:   160,
		ProtoType: 1,
		Version:   1,
		Reserve:   0,
		LocalPort: 9090,
	}

	sessionIDStr := c.sessionMap["session_id"]
	//log.Printf("客户端 %d 使用 session_id: %s", c.id, sessionIDStr)
	copy(header.SessionID[:], []byte(sessionIDStr))

	appName := "zjtXh9c5uOY8N7wa"
	copy(header.AppName[:], []byte(appName))

	bytesRequest, err := header.Marshal()
	if err != nil {
		log.Printf("客户端 %d Marshal header error: %s", c.id, err)
		return false
	}

	_, err = uconn.Write(bytesRequest)
	if err != nil {
		log.Printf("客户端 %d Send header error: %s", c.id, err)
		return false
	}

	// 读取并解析服务器响应
	uconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := uconn.Read(response)
	if err != nil {
		log.Printf("客户端 %d Read error: %s", c.id, err)
		return false
	}

	if n < 20 {
		log.Printf("❌❌ 客户端 %d: 接收数据不足: %d 字节 (需要至少20字节)", c.id, n)
		return false
	}

	// 发送业务请求
	c.sendTCPHello(uconn)
	//log.Printf("✅ 客户端 %d TCP执行完成", c.id)
	return true
}

// 发送第三方业务请求
func (c *Client) sendTCPHello(conn net.Conn) bool {
	request := "GET /hello HTTP/1.0\r\n" +
		"Host: 10.10.27.97:9090\r\n" +
		"User-Agent: curl/7.68.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"

	_, err := conn.Write([]byte(request))
	if err != nil {
		log.Printf("客户端 %d Error sending request: %s", c.id, err)
		return false
	}

	// 只读取少量数据（足够获取状态码）
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		log.Printf("客户端 %d Error reading response: %s", c.id, err)
		return false
	}
	// 检查是否包含"200"状态码
	if bytes.Contains(buffer[:n], []byte(" 200 ")) {
		return true
	}
	log.Printf("❌❌ 客户端 %d 业务请求失败", c.id)
	return false
}

// 更新统计信息
func (cm *ClientManager) updateStats(success bool) {
	if success {
		atomic.AddInt32(&cm.successCount, 1)
	} else {
		atomic.AddInt32(&cm.failCount, 1)
	}
}

// 获取统计信息
func (cm *ClientManager) getStats() (int, int, time.Duration) {
	cm.statsMutex.Lock()
	defer cm.statsMutex.Unlock()

	cm.totalTime = time.Since(cm.startTime)
	// 使用原子加载值
	success := int(atomic.LoadInt32(&cm.successCount))
	fail := int(atomic.LoadInt32(&cm.failCount))
	return success, fail, cm.totalTime
}

// ====================== 主函数 ======================
func main() {
	// 设置并发客户端数量
	// 加载配置文件
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("❌❌❌❌ 加载配置文件失败: %v", err)
	}

	// 使用配置值替换硬编码值
	clientCount := config.ClientCount
	runDuration := time.Duration(config.RunDuration) * time.Second
	host := config.Host
	port := config.Port

	// 创建客户端管理器
	cm, err := NewClientManager(0)
	if err != nil {
		log.Fatalf("❌❌❌❌ 创建客户端管理器失败: %v", err)
	}

	log.Printf("🚀🚀🚀🚀 启动 %d 个并行客户端，运行时间: %v", clientCount, runDuration)

	// 设置运行截止时间
	endTime := time.Now().Add(runDuration)

	// 使用通道控制并发
	semaphore := make(chan struct{}, clientCount)
	var wg sync.WaitGroup

	// 用于循环使用数据行的索引
	sessionIndex := 0
	tokenIndex := 0
	clientID := 0

	// 在主循环中持续运行客户端
	for time.Now().Before(endTime) {
		semaphore <- struct{}{} // 获取信号量
		wg.Add(1)

		go func(sessIdx, tokIdx, id int) {
			defer wg.Done()
			defer func() { <-semaphore }() //释放信号量

			// 动态创建session映射
			sessionMap := make(map[string]string)
			for j, header := range cm.sessionHeaders {
				if j < len(cm.sessionData[sessIdx]) {
					sessionMap[header] = strings.TrimSpace(cm.sessionData[sessIdx][j])
				}
			}

			// 动态创建token映射
			tokenMap := make(map[string]string)
			for j, header := range cm.tokenHeaders {
				if j < len(cm.tokenData[tokIdx]) {
					tokenMap[header] = strings.TrimSpace(cm.tokenData[tokIdx][j])
				}
			}
			// 创建新的客户端实例
			client := &Client{
				id:         id,
				sessionMap: sessionMap,
				tokenMap:   tokenMap,
			}
			clientStartTime := time.Now()
			success := client.runTCPClient(host, port)
			client.success = success

			// 更新统计信息
			cm.updateStats(success)
			clientTime := time.Since(clientStartTime)

			if success {
				//log.Printf("✅✅ 客户端 %d 执行成功, 耗时: %v", id, clientTime)
			} else {
				log.Printf("❌❌ 客户端 %d 执行失败, 耗时: %v", id, clientTime)
			}
		}(sessionIndex, tokenIndex, clientID)

		// 更新索引，循环使用数据行
		sessionIndex = (sessionIndex + 1) % len(cm.sessionData)
		tokenIndex = (tokenIndex + 1) % len(cm.tokenData)
		clientID++
	}
	// 等待所有已启动的客户端完成
	wg.Wait()

	// 获取最终统计信息
	successCount, failCount, totalTime := cm.getStats()
	var tps float64
	if totalTime.Seconds() > 0 {
		tps = float64(successCount) / totalTime.Seconds()
	}

	// 打印详细统计报告
	log.Printf("🎊🎊🎊🎊🎊🎊🎊🎊 运行完成! 总运行时间: %v", runDuration)
	log.Printf("📊📊📊📊📊📊📊📊 ========== 统计报告 ==========")
	log.Printf("📊📊📊📊📊📊📊📊 实际运行时间: %v", totalTime)
	log.Printf("📊📊📊📊📊📊📊📊 成功次数: %d", successCount)
	log.Printf("📊📊📊📊📊📊📊📊 失败次数: %d", failCount)
	totalRequests := successCount + failCount
	if totalRequests > 0 {
		log.Printf("📊📊📊📊📊📊📊📊 成功率: %.2f%%", float64(successCount)/float64(totalRequests)*100)
	} else {
		log.Printf("📊📊📊📊📊📊📊📊 成功率: 0.00%%")
	}
	log.Printf("📊📊📊📊📊📊📊📊 TPS: %.2f (每秒处理事务数)", tps)
	log.Printf("📊📊📊📊📊📊📊📊 ==============================")
}
