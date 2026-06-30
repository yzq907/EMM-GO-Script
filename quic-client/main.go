package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
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
// SPA协议头结构
type SPAHeader struct {
	Tag       uint32 // "SPA:" ASCII码值 (83,80,65,58)
	Version   uint16
	Command   uint16
	ProtoType uint8
	Option    uint8
	Reserve   uint16
	DataLen   uint32
	OriginLen uint32
}

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

// TokenInfo 结构体
type TokenInfo struct {
	DevID     string `json:"devid"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Token     string `json:"token"`
}

// 客户端结构体
type Client struct {
	id        int
	tokenInfo string
	tokenLock sync.Mutex
	lineIndex int
	credMap   map[string]string
	success   bool
}

// 客户端管理器
type ClientManager struct {
	mu           sync.Mutex
	csvHeaders   []string
	csvLines     [][]string
	startTime    time.Time
	totalTime    time.Duration
	successCount int32
	failCount    int32
	statsMutex   sync.Mutex
}

// 配置文件结构体
type Config struct {
	Host         string `json:"host"`
	Port         string `json:"port"`
	ClientCount  int    `json:"client_count"`
	RunDuration  int    `json:"run_duration_s"`
	AuthPassword string `json:"auth_password"`
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

// 加载配置文件
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
	if config.AuthPassword == "" {
		return nil, errors.New("配置文件中auth_password字段不能为空")
	}

	return &config, nil
}

// 创建客户端管理器
func NewClientManager(clientCount int) (*ClientManager, error) {
	// 加载用户凭证数据
	headers, dataLines, err := loadCSVData("userinfo.csv")
	if err != nil {
		return nil, err
	}

	cm := &ClientManager{
		csvHeaders: headers,
		csvLines:   dataLines,
		startTime:  time.Now(),
	}

	return cm, nil
}

// ====================== QUIC 客户端功能 ======================
func (c *Client) runQUICClient(cm *ClientManager, host, port string) error {
	//log.Printf("🚀🚀 启动QUIC客户端 %d...", c.id)
	address := net.JoinHostPort(host, port)

	// 检查必需的字段
	requiredFields := []string{"devid", "username"}
	//log.Printf("🔑🔑 客户端 %d 使用凭证: devid=%s, username=%s", c.id, c.credMap["devid"], c.credMap["username"])
	for _, field := range requiredFields {
		if _, ok := c.credMap[field]; !ok {
			return fmt.Errorf("❌❌ 客户端 %d: CSV文件中缺少必需的字段: %s", c.id, field)
		}
	}

	// 创建认证请求体
	authRequest := map[string]interface{}{
		"requestid":      uuid.New().String(),
		"devid":          c.credMap["devid"],
		"username":       c.credMap["username"],
		"password":       c.credMap["auth_password"],
		"authType":       0,
		"strpackagename": "com.leagsoft.emm",
		"codetype":       "0",
		"Version":        "5.4",
	}

	// 运行客户端
	if err := c.sendSPARequest(address, authRequest); err != nil {
		return err
	}
	return nil
}

func (c *Client) sendSPARequest(address string, authRequest map[string]interface{}) error {
	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos: []string{
			"hq-interop", "h3-23", "h3-24", "h3-25", "hq-29", "hq-28", "hq-27", "http/0.9",
		},
	}

	// 创建QUIC配置
	quicConfig := &quic.Config{
		KeepAlivePeriod: 5 * time.Second,
		MaxIdleTimeout:  MaxIdleTimeout,
	}

	// 连接到服务器
	ctx, cancel := context.WithTimeout(context.Background(), QUICDialTimeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, address, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("连接失败: %w", err)
	}
	defer conn.CloseWithError(0, "client closed")

	streamCtx, streamCancel := context.WithTimeout(context.Background(), QUICStreamTimeout)
	defer streamCancel()
	// 打开流
	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		return fmt.Errorf("打开流失败: %w", err)
	}
	defer stream.Close()

	// 发送认证请求
	if err := c.sendQUICAuthRequest(stream, authRequest); err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}

	// 接收响应
	response, err := c.receiveSPAResponse(stream)
	if err != nil {
		return fmt.Errorf("接收响应失败: %w", err)
	}

	devid, ok := authRequest["devid"].(string)
	if !ok {
		return fmt.Errorf("devid 字段类型错误或不存在")
	}

	if err := c.processTokenInfo(response, devid); err != nil {
		log.Printf("❌❌ 客户端 %d 处理 token 信息失败: %v", c.id, err)
	}

	return nil
}

func (c *Client) processTokenInfo(response map[string]interface{}, devid string) error {
	// 提取所需字段
	timestamp, ok := response["timestamp"]
	if !ok {
		return errors.New("timestamp 字段缺失")
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
			return fmt.Errorf("timestamp 类型转换失败: %w", err)
		}
		timestampInt = ts
	default:
		return fmt.Errorf("timestamp 类型错误: %T", v)
	}

	nonce, ok := response["nonce"].(string)
	if !ok {
		return errors.New("nonce 字段缺失或类型错误")
	}

	token, ok := response["token"].(string)
	if !ok {
		return errors.New("token 字段缺失或类型错误")
	}

	// 创建 TokenInfo 结构体
	info := TokenInfo{
		DevID:     devid,
		Timestamp: timestampInt,
		Nonce:     nonce,
		Token:     token,
	}

	// 序列化为 JSON
	jsonData, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("序列化 token 信息失败: %w", err)
	}

	// Base64 编码
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	// 安全地更新客户端token
	filename := "token_client.csv"

	// 以追加模式打开文件，如果不存在则创建
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 写入CSV格式的数据
	writer := csv.NewWriter(file)
	fileInfo, err := os.Stat(filename)
	if err == nil && fileInfo.Size() == 0 {
		// 文件为空，写入标题行
		headerRecord := []string{"token_id"}
		if err := writer.Write(headerRecord); err != nil {
			return fmt.Errorf("写入CSV标题行失败: %w", err)
		}
	}
	record := []string{
		encoded, // base64编码的token
	}

	if err := writer.Write(record); err != nil {
		return fmt.Errorf("写入CSV文件失败: %w", err)
	}
	writer.Flush()

	// 安全地更新客户端token（如果其他地方还需要）
	return nil
}

func (c *Client) sendQUICAuthRequest(stream *quic.Stream, authRequest map[string]interface{}) error {
	// 创建SPA消息头
	header := SPAHeader{
		Tag:       0x5350413A,
		Version:   1,
		Command:   AUTH_REQUEST,
		ProtoType: JSON,
		Option:    0,
		Reserve:   0,
		OriginLen: 0,
	}

	// 序列化消息体
	bodyBytes, err := json.Marshal(authRequest)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %w", err)
	}

	header.DataLen = uint32(len(bodyBytes))

	// 打包消息头
	headerBytes := make([]byte, 20)
	binary.BigEndian.PutUint32(headerBytes[0:4], header.Tag)
	binary.BigEndian.PutUint16(headerBytes[4:6], header.Version)
	binary.BigEndian.PutUint16(headerBytes[6:8], header.Command)
	headerBytes[8] = header.ProtoType
	headerBytes[9] = header.Option
	binary.BigEndian.PutUint16(headerBytes[10:12], header.Reserve)
	binary.BigEndian.PutUint32(headerBytes[12:16], header.DataLen)
	binary.BigEndian.PutUint32(headerBytes[16:20], header.OriginLen)

	if err := stream.SetWriteDeadline(time.Now().Add(QUICStreamTimeout)); err != nil {
		return err
	}
	// 发送消息头
	if _, err := stream.Write(headerBytes); err != nil {
		return fmt.Errorf("发送消息头失败: %w", err)
	}

	// 发送消息体
	if _, err := stream.Write(bodyBytes); err != nil {
		return fmt.Errorf("发送消息体失败: %w", err)
	}

	return nil
}

func (c *Client) receiveSPAResponse(stream *quic.Stream) (map[string]interface{}, error) {
	if err := stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, fmt.Errorf("设置读取超时失败: %w", err)
	}

	// 读取完整的响应头（20字节）
	headerBytes := make([]byte, 20)
	if _, err := io.ReadFull(stream, headerBytes); err != nil {
		return nil, fmt.Errorf("读取响应头失败: %w", err)
	}

	// 解析消息头
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
	n, err := stream.Read(bodyBytes)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}

	bodyBytes = bodyBytes[:n]

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
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("❌❌❌❌ 加载配置文件失败: %v", err)
	}

	// 使用配置值替换硬编码值
	clientCount := config.ClientCount
	runDuration := time.Duration(config.RunDuration) * time.Second // 改为秒
	host := config.Host
	port := config.Port
	// 设置并发客户端数量

	// 创建客户端管理器
	cm, err := NewClientManager(0) // 传入0，不预先创建客户端
	if err != nil {
		log.Fatalf("❌❌ 创建客户端管理器失败: %v", err)
	}

	log.Printf("🚀🚀 启动 %d 个并行客户端，运行时间: %v", clientCount, runDuration)

	// 设置运行截止时间
	endTime := time.Now().Add(runDuration)

	// 使用通道控制并发
	semaphore := make(chan struct{}, clientCount)
	var wg sync.WaitGroup

	// 用于循环使用数据行的索引
	dataIndex := 0
	clientID := 0

	// 在主循环中持续运行客户端
	for time.Now().Before(endTime) {
		semaphore <- struct{}{} // 获取信号量
		wg.Add(1)

		go func(dataIdx, id int) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			// 动态创建凭证映射
			credMap := make(map[string]string)
			for j, header := range cm.csvHeaders {
				if j < len(cm.csvLines[dataIdx]) {
					credMap[header] = strings.TrimSpace(cm.csvLines[dataIdx][j])
				}
			}
			client := &Client{
				id:      id,
				credMap: credMap,
			}
			client.credMap["auth_password"] = config.AuthPassword
			// 执行客户端
			if err := client.runQUICClient(cm, host, port); err != nil {
				log.Printf("❌❌ 客户端 %d QUIC认证失败: %v", id, err)
				cm.updateStats(false)
				return
			}
			//log.Printf("✅✅ 客户端 %d QUIC认证成功", id)
			cm.updateStats(true)
		}(dataIndex, clientID)

		// 更新索引，循环使用数据行
		dataIndex = (dataIndex + 1) % len(cm.csvLines)
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
	log.Printf("🎊🎊🎊🎊 运行完成! 总运行时间: %v", runDuration)
	log.Printf("📊📊📊📊 ========== 统计报告 ==========")
	log.Printf("📊📊📊📊 实际运行时间: %v", totalTime)
	log.Printf("📊📊📊📊 成功次数: %d", successCount)
	log.Printf("📊📊📊📊 失败次数: %d", failCount)
	totalRequests := successCount + failCount
	if totalRequests > 0 {
		log.Printf("📊📊📊📊 成功率: %.2f%%", float64(successCount)/float64(totalRequests)*100)
	} else {
		log.Printf("📊📊📊📊 成功率: 0.00%%")
	}
	log.Printf("📊📊📊📊 TPS: %.2f (每秒处理事务数)", tps)
	log.Printf("📊📊📊📊 ==============================")
}
