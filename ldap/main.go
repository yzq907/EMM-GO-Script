package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"
)

type Config struct {
	LDAP struct {
		Address        string `yaml:"address"`
		BindDN         string `yaml:"bind_dn"`
		Password       string `yaml:"password"`
		BaseDN         string `yaml:"base_dn"`
		UserFilter     string `yaml:"user_filter"`
		UserDNTemplate string `yaml:"user_dn_template"`
	} `yaml:"ldap"`

	StressTest struct {
		ConcurrentUsers int    `yaml:"concurrent_users"`
		DurationSeconds int    `yaml:"duration_seconds"`
		UserDataFile    string `yaml:"user_data_file"`
	} `yaml:"stress_test"`
}

type Stats struct {
	TotalRequests   int64
	SuccessCount    int64
	FailureCount    int64
	StartTime       time.Time
	EndTime         time.Time
	MinTime         int64
	MaxTime         int64
	TotalLatency    int64
	ErrorDetails    map[string]int64
	errorDetailsMux sync.Mutex
}

func main() {
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	users, err := loadUsers(config.StressTest.UserDataFile)
	if err != nil {
		log.Fatalf("加载用户数据失败: %v", err)
	}

	if len(users) == 0 {
		log.Fatal("用户数据为空，请检查data.csv文件")
	}

	log.Printf("配置信息:")
	log.Printf("  LDAP地址: %s", config.LDAP.Address)
	log.Printf("  并发用户数: %d", config.StressTest.ConcurrentUsers)
	log.Printf("  测试时长: %d秒", config.StressTest.DurationSeconds)
	log.Printf("  用户数量: %d", len(users))
	log.Printf("开始启动worker...")

	stats := &Stats{
		ErrorDetails: make(map[string]int64),
		StartTime:    time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.StressTest.DurationSeconds)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	userChan := make(chan string, config.StressTest.ConcurrentUsers*10)

	for i := 0; i < config.StressTest.ConcurrentUsers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, userChan, config, stats)
	}

	log.Printf("启动了 %d 个worker", config.StressTest.ConcurrentUsers)
	log.Printf("开始发送用户数据...")

	go func() {
		defer close(userChan)
		requestCount := 0
		for {
			select {
			case <-ctx.Done():
				log.Printf("测试结束，共发送 %d 个请求", requestCount)
				return
			default:
				for _, user := range users {
					select {
					case userChan <- user:
						requestCount++
					case <-ctx.Done():
						log.Printf("测试结束，共发送 %d 个请求", requestCount)
						return
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	log.Printf("所有worker已完成")

	printStats(stats)
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func loadUsers(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			users = append(users, line)
		}
	}

	return users, scanner.Err()
}

func worker(ctx context.Context, wg *sync.WaitGroup, userChan <-chan string, config *Config, stats *Stats) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case username, ok := <-userChan:
			if !ok {
				return
			}
			authenticateUser(username, config, stats)
		}
	}
}

func authenticateUser(username string, config *Config, stats *Stats) {
	startTime := time.Now()
	atomic.AddInt64(&stats.TotalRequests, 1)

	l, err := ldap.DialURL(config.LDAP.Address)
	if err != nil {
		log.Printf("连接LDAP失败: %v", err)
		recordFailure(stats, err, startTime)
		return
	}
	defer l.Close()

	userDN := fmt.Sprintf(config.LDAP.UserDNTemplate, username)

	connCtx, connCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer connCancel()

	done := make(chan error, 1)
	go func() {
		done <- l.Bind(userDN, config.LDAP.Password)
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Printf("认证失败 [%s]: %v", username, err)
			recordFailure(stats, err, startTime)
			return
		}
	case <-connCtx.Done():
		log.Printf("认证超时 [%s]", username)
		recordFailure(stats, fmt.Errorf("认证超时"), startTime)
		return
	}

	duration := time.Since(startTime)
	recordSuccess(stats, duration)
}

func recordSuccess(stats *Stats, duration time.Duration) {
	atomic.AddInt64(&stats.SuccessCount, 1)
	durationMs := int64(duration.Milliseconds())
	atomic.AddInt64(&stats.TotalLatency, durationMs)

	for {
		currentMin := atomic.LoadInt64(&stats.MinTime)
		if currentMin == 0 || durationMs < currentMin {
			if atomic.CompareAndSwapInt64(&stats.MinTime, currentMin, durationMs) {
				break
			}
		} else {
			break
		}
	}

	for {
		currentMax := atomic.LoadInt64(&stats.MaxTime)
		if durationMs > currentMax {
			if atomic.CompareAndSwapInt64(&stats.MaxTime, currentMax, durationMs) {
				break
			}
		} else {
			break
		}
	}
}

func recordFailure(stats *Stats, err error, startTime time.Time) {
	atomic.AddInt64(&stats.FailureCount, 1)
	_ = time.Since(startTime)

	stats.errorDetailsMux.Lock()
	stats.ErrorDetails[err.Error()]++
	stats.errorDetailsMux.Unlock()
}

func printStats(stats *Stats) {
	totalRequests := atomic.LoadInt64(&stats.TotalRequests)
	successCount := atomic.LoadInt64(&stats.SuccessCount)
	failureCount := atomic.LoadInt64(&stats.FailureCount)
	totalLatency := atomic.LoadInt64(&stats.TotalLatency)
	minTime := atomic.LoadInt64(&stats.MinTime)
	maxTime := atomic.LoadInt64(&stats.MaxTime)

	testDuration := time.Since(stats.StartTime).Seconds()
	tps := float64(successCount) / testDuration

	fmt.Println("\n========== 压力测试结果 ==========")
	fmt.Printf("测试时长: %.2f 秒\n", testDuration)
	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("成功数: %d\n", successCount)
	fmt.Printf("失败数: %d\n", failureCount)
	fmt.Printf("成功率: %.2f%%\n", float64(successCount)/float64(totalRequests)*100)
	fmt.Printf("失败率: %.2f%%\n", float64(failureCount)/float64(totalRequests)*100)
	fmt.Printf("TPS (每秒事务数): %.2f\n", tps)

	if successCount > 0 {
		avgLatency := float64(totalLatency) / float64(successCount)
		fmt.Printf("平均响应时间: %.2f ms\n", avgLatency)
		fmt.Printf("最小响应时间: %d ms\n", minTime)
		fmt.Printf("最大响应时间: %d ms\n", maxTime)
	}

	if len(stats.ErrorDetails) > 0 {
		fmt.Println("\n错误详情:")
		for errMsg, count := range stats.ErrorDetails {
			fmt.Printf("  %s: %d 次\n", errMsg, count)
		}
	}
	fmt.Println("==================================")
}
