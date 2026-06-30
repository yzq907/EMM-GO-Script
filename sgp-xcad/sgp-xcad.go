package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// KDCConfig 统一的配置结构体
type KDCConfig struct {
	// 基础配置
	Realm         string        `yaml:"realm"`
	KDC           string        `yaml:"kdc"`
	AdminServer   string        `yaml:"admin_server"`
	KPasswdServer string        `yaml:"kpasswd_server"`
	KDCIP         string        `yaml:"kdc_ip"`
	Timeout       time.Duration `yaml:"timeout"` // 秒

	// 认证配置
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`

	// 测试配置
	TotalRequests int    `yaml:"total_requests"`
	Concurrency   int    `yaml:"concurrency"`
	UserFile      string `yaml:"user_file"`

	// 性能配置
	MaxRetries         int `yaml:"max_retries"`
	UdpPreferenceLimit int `yaml:"udp_preference_limit"`
}

// 统计结构体
type Statistics struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalTime       int64
	MaxResponseTime int64
	MinResponseTime int64
	StartTime       time.Time
}

var (
	stats Statistics
)

// 初始化统计
func init() {
	stats = Statistics{
		MinResponseTime: int64(time.Hour),
		StartTime:       time.Now(),
	}
}

// LoadConfig 从YAML文件加载配置
func LoadConfig(filename string) (*KDCConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config KDCConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 设置默认值
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second // 5秒
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 1
	}
	if config.UdpPreferenceLimit == 0 {
		config.UdpPreferenceLimit = 1
	}
	if config.TotalRequests == 0 {
		config.TotalRequests = 100
	}
	if config.Concurrency == 0 {
		config.Concurrency = 20
	}
	if config.UserFile == "" {
		config.UserFile = "users.dat"
	}

	return &config, nil
}

// 从文件读取用户列表
func readUsersFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开用户文件: %v", err)
	}
	defer file.Close()

	var users []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		if username != "" && !strings.HasPrefix(username, "#") {
			users = append(users, username)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取用户文件失败: %v", err)
	}

	return users, nil
}

// 打印统计信息
func (s *Statistics) Print() {
	totalRequests := atomic.LoadInt64(&s.TotalRequests)
	successRequests := atomic.LoadInt64(&s.SuccessRequests)
	failedRequests := atomic.LoadInt64(&s.FailedRequests)
	totalTime := atomic.LoadInt64(&s.TotalTime)
	maxResponseTime := atomic.LoadInt64(&s.MaxResponseTime)
	minResponseTime := atomic.LoadInt64(&s.MinResponseTime)

	totalRunTime := time.Since(s.StartTime)
	var successRate float64
	if totalRequests > 0 {
		successRate = float64(successRequests) / float64(totalRequests) * 100
	}
	tps := float64(totalRequests) / totalRunTime.Seconds()

	fmt.Printf("\n=== 执行统计 ===\n")
	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("成功请求数: %d (%.3f%%)\n", successRequests, successRate)
	fmt.Printf("失败请求数: %d\n", failedRequests)
	if totalRequests > 0 {
		fmt.Printf("平均响应时间: %v\n", time.Duration(totalTime)/time.Duration(totalRequests))
	} else {
		fmt.Printf("平均响应时间: 0\n")
	}
	fmt.Printf("最大响应时间: %v\n", time.Duration(maxResponseTime))
	fmt.Printf("最小响应时间: %v\n", time.Duration(minResponseTime))
	fmt.Printf("总运行时间: %v\n", totalRunTime)
	fmt.Printf("TPS: %.2f\n", tps)
}

// CreateKRB5Config 创建优化的Kerberos配置文件内容
func CreateKRB5Config(cfg *KDCConfig) string {
	// 预编译常用值，减少重复计算
	realm := cfg.Realm
	kdcIP := cfg.KDCIP
	lowerRealm := strings.ToLower(realm)
	adminServer := cfg.AdminServer

	return fmt.Sprintf(`
[libdefaults]
 default_realm = %s
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 udp_preference_limit = %d
 kdc_timeout = %v
 max_retries = %d

[realms]
 %s = {
  kdc = %s:88
  admin_server = %s
  default_domain = %s
 }

[domain_realm]
 .%s = %s
 %s = %s
`, realm, cfg.UdpPreferenceLimit, cfg.Timeout,
		cfg.MaxRetries, realm, kdcIP, adminServer, lowerRealm,
		lowerRealm, realm, lowerRealm, realm)
}

// LoginWithPassword 使用密码认证（带超时控制）
func LoginWithPassword(cfg *KDCConfig, username string) error {
	krbConfig, err := config.NewFromString(CreateKRB5Config(cfg))
	if err != nil {
		return fmt.Errorf("创建Kerberos配置失败: %v", err)
	}

	cl := client.NewWithPassword(
		username,
		cfg.Realm,
		cfg.Password,
		krbConfig,
		client.DisablePAFXFAST(true),
	)

	err = cl.Login()
	if err != nil {
		return fmt.Errorf("KDC认证失败: %v", err)
	}

	defer cl.Destroy()

	return nil
}

// 批量处理认证请求
func processAuthRequests(cfg *KDCConfig, users []string, totalRequests int, concurrency int) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	log.Printf("开始执行认证测试，总次数: %d, 并发数: %d, 用户数: %d",
		totalRequests, concurrency, len(users))

	if len(users) == 0 {
		log.Printf("错误: 用户列表为空")
		return
	}

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(requestID int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			start := time.Now()
			success := false

			userIndex := requestID % len(users)
			username := users[userIndex]

			err := LoginWithPassword(cfg, username)
			if err != nil {
				log.Printf("请求 %d (用户 %s): 认证失败: %v", requestID, username, err)
			} else {
				success = true
			}

			duration := time.Since(start)
			// 更新统计信息
			atomic.AddInt64(&stats.TotalRequests, 1)
			if success {
				atomic.AddInt64(&stats.SuccessRequests, 1)
			} else {
				atomic.AddInt64(&stats.FailedRequests, 1)
			}
			atomic.AddInt64(&stats.TotalTime, int64(duration))

			// 更新最大响应时间
			for {
				currentMax := atomic.LoadInt64(&stats.MaxResponseTime)
				if int64(duration) <= currentMax || atomic.CompareAndSwapInt64(&stats.MaxResponseTime, currentMax, int64(duration)) {
					break
				}
			}

			// 更新最小响应时间
			for {
				currentMin := atomic.LoadInt64(&stats.MinResponseTime)
				if int64(duration) >= currentMin || atomic.CompareAndSwapInt64(&stats.MinResponseTime, currentMin, int64(duration)) {
					break
				}
			}
		}(i)
	}

	wg.Wait()
	log.Printf("所有认证请求处理完成")
}

func main() {
	start := time.Now()

	fmt.Println("=== KDC批量认证压力测试开始 ===")

	// 从配置文件加载配置
	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 读取用户文件
	users, err := readUsersFromFile(cfg.UserFile)
	if err != nil {
		log.Fatalf("读取用户文件失败: %v", err)
	}

	if len(users) == 0 {
		log.Fatalf("用户文件为空或没有有效的用户")
	}

	fmt.Printf("📊 用户文件包含 %d 个用户\n", len(users))
	fmt.Printf("🎯 测试配置: 总次数=%d, 并发数=%d\n", cfg.TotalRequests, cfg.Concurrency)

	// 执行认证测试
	processAuthRequests(cfg, users, cfg.TotalRequests, cfg.Concurrency)

	// 打印最终统计信息
	stats.Print()

	totalTime := time.Since(start)
	fmt.Printf("\n=== 压力测试完成 ===\n")
	fmt.Printf("总执行时间: %v\n", totalTime)

	if stats.SuccessRequests < int64(cfg.TotalRequests) {
		fmt.Printf("⚠️ 有部分请求失败，建议检查KDC服务器状态和网络连接\n")
	}
}