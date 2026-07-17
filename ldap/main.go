package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"
)

const (
	ScenarioBind             = "bind"
	ScenarioSearch           = "search"
	ScenarioModify           = "modify"
	ScenarioBindSearch       = "bind_search"
	ScenarioBindSearchModify = "bind_search_modify"
	ScenarioMixed            = "mixed"

	WriteScheduleRatio = "ratio"
	WriteScheduleRate  = "rate"

	LDAPScopeBaseObject   = 0
	LDAPScopeSingleLevel  = 1
	LDAPScopeWholeSubtree = 2

	LDAPModifyReplace = "replace"
	LDAPModifyAdd     = "add"
	LDAPModifyDelete  = "delete"
)

type Config struct {
	LDAP struct {
		Address                  string   `yaml:"address"`
		BindDN                   string   `yaml:"bind_dn"`
		Password                 string   `yaml:"password"`
		AdminBindDN              string   `yaml:"admin_bind_dn"`
		AdminPassword            string   `yaml:"admin_password"`
		BaseDN                   string   `yaml:"base_dn"`
		UserFilter               string   `yaml:"user_filter"`
		UserDNTemplate           string   `yaml:"user_dn_template"`
		SearchBaseTemplate       string   `yaml:"search_base_template"`
		SearchFilterTemplate     string   `yaml:"search_filter_template"`
		SearchAttributes         []string `yaml:"search_attributes"`
		SearchScope              int      `yaml:"search_scope"`
		SearchCountLimit         int      `yaml:"search_count_limit"`
		ModifyAttribute          string   `yaml:"modify_attribute"`
		ModifyOperation          string   `yaml:"modify_operation"`
		ModifyValueTemplate      string   `yaml:"modify_value_template"`
		VerifyModify             bool     `yaml:"verify_modify"`
		ConnectionTimeoutSeconds int      `yaml:"connection_timeout_seconds"`
		OperationTimeoutSeconds  int      `yaml:"operation_timeout_seconds"`
	} `yaml:"ldap"`

	StressTest struct {
		ConcurrentUsers       int    `yaml:"concurrent_users"`
		DurationSeconds       int    `yaml:"duration_seconds"`
		UserDataFile          string `yaml:"user_data_file"`
		Scenario              string `yaml:"scenario"`
		ReadConcurrentUsers   int    `yaml:"read_concurrent_users"`
		WriteConcurrentUsers  int    `yaml:"write_concurrent_users"`
		WriteIntervalRequests int    `yaml:"write_interval_requests"`
		WriteSchedule         string `yaml:"write_schedule"`
		WriteRatePerSecond    int    `yaml:"write_rate_per_second"`
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

type LDAPClient interface {
	Bind(username, password string) error
	Search(req LDAPSearchRequest) (*LDAPSearchResult, error)
	Modify(req LDAPModifyRequest) error
	Close()
}

type LDAPSearchRequest struct {
	BaseDN     string
	Scope      int
	Filter     string
	Attributes []string
	CountLimit int
}

type LDAPSearchResult struct {
	Entries []LDAPEntry
}

type LDAPEntry struct {
	DN         string
	Attributes map[string][]string
}

type LDAPModifyRequest struct {
	DN        string
	Operation string
	Attribute string
	Value     string
}

type ScenarioResult struct {
	Success bool
	Step    string
	Err     error
}

type goLDAPClient struct {
	conn *ldap.Conn
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
	log.Printf("  测试场景: %s", config.StressTest.Scenario)
	log.Printf("  用户数量: %d", len(users))

	if config.StressTest.Scenario == ScenarioMixed {
		runMixedStressTest(config, users)
		return
	}

	stats := runSingleStressTest(config, users)
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

	applyConfigDefaults(&config)
	return &config, nil
}

func applyConfigDefaults(config *Config) {
	if config.StressTest.Scenario == "" {
		config.StressTest.Scenario = ScenarioBind
	}
	if config.LDAP.SearchBaseTemplate == "" {
		config.LDAP.SearchBaseTemplate = config.LDAP.UserDNTemplate
	}
	if config.LDAP.SearchFilterTemplate == "" {
		if config.LDAP.UserFilter != "" {
			config.LDAP.SearchFilterTemplate = config.LDAP.UserFilter
		} else {
			config.LDAP.SearchFilterTemplate = "(&(objectClass=person)(cn=%s))"
		}
	}
	if config.LDAP.SearchAttributes == nil {
		config.LDAP.SearchAttributes = []string{"cn", "distinguishedName", "objectClass"}
	}
	if config.LDAP.SearchScope < LDAPScopeBaseObject || config.LDAP.SearchScope > LDAPScopeWholeSubtree {
		config.LDAP.SearchScope = LDAPScopeBaseObject
	}
	if config.LDAP.SearchCountLimit == 0 {
		config.LDAP.SearchCountLimit = 1
	}
	if config.LDAP.ModifyAttribute == "" {
		config.LDAP.ModifyAttribute = "description"
	}
	if config.LDAP.ModifyOperation == "" {
		config.LDAP.ModifyOperation = LDAPModifyReplace
	}
	if config.LDAP.ModifyValueTemplate == "" {
		config.LDAP.ModifyValueTemplate = "go-write-%s-%d"
	}
	if config.LDAP.ConnectionTimeoutSeconds == 0 {
		config.LDAP.ConnectionTimeoutSeconds = 10
	}
	if config.LDAP.OperationTimeoutSeconds == 0 {
		config.LDAP.OperationTimeoutSeconds = 60
	}
	if config.StressTest.ReadConcurrentUsers == 0 {
		config.StressTest.ReadConcurrentUsers = config.StressTest.ConcurrentUsers
	}
	if config.StressTest.WriteConcurrentUsers == 0 {
		config.StressTest.WriteConcurrentUsers = 1
	}
	if config.StressTest.WriteIntervalRequests == 0 {
		config.StressTest.WriteIntervalRequests = 1000
	}
	if config.StressTest.WriteSchedule == "" {
		config.StressTest.WriteSchedule = WriteScheduleRatio
	}
	if config.StressTest.WriteRatePerSecond == 0 {
		config.StressTest.WriteRatePerSecond = 1
	}
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

func newStats(startTime time.Time) *Stats {
	return &Stats{
		ErrorDetails: make(map[string]int64),
		StartTime:    startTime,
	}
}

func runSingleStressTest(config *Config, users []string) *Stats {
	log.Printf("开始启动worker...")
	stats := newStats(time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.StressTest.DurationSeconds)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	userChan := make(chan string, config.StressTest.ConcurrentUsers*10)

	for i := 0; i < config.StressTest.ConcurrentUsers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, userChan, config, stats, config.StressTest.Scenario)
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
	return stats
}

func runMixedStressTest(config *Config, users []string) {
	log.Printf("开始启动混合负载worker...")
	log.Printf("  读场景: %s, 读worker: %d", ScenarioBindSearch, config.StressTest.ReadConcurrentUsers)
	if config.StressTest.WriteSchedule == WriteScheduleRate {
		log.Printf("  写场景: %s, 写worker: %d, 写入策略: 全局定速 %d 次/秒", ScenarioModify, config.StressTest.WriteConcurrentUsers, config.StressTest.WriteRatePerSecond)
	} else {
		log.Printf("  写场景: %s, 写worker: %d, 写入策略: 每 %d 次读触发 1 次写", ScenarioModify, config.StressTest.WriteConcurrentUsers, config.StressTest.WriteIntervalRequests)
	}

	startTime := time.Now()
	readStats := newStats(startTime)
	writeStats := newStats(startTime)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.StressTest.DurationSeconds)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	readChan := make(chan string, config.StressTest.ReadConcurrentUsers*10)
	writeChan := make(chan string, config.StressTest.WriteConcurrentUsers*10)

	for i := 0; i < config.StressTest.ReadConcurrentUsers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, readChan, config, readStats, ScenarioBindSearch)
	}
	for i := 0; i < config.StressTest.WriteConcurrentUsers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, writeChan, config, writeStats, ScenarioModify)
	}

	go func() {
		defer close(readChan)
		defer close(writeChan)
		if config.StressTest.WriteSchedule == WriteScheduleRate {
			feedMixedRateWork(ctx, users, readChan, writeChan, config.StressTest.WriteRatePerSecond)
			return
		}
		feedMixedRatioWork(ctx, users, readChan, writeChan, config.StressTest.WriteIntervalRequests)
	}()

	wg.Wait()
	log.Printf("所有混合负载worker已完成")
	printMixedStats(readStats, writeStats)
}

func shouldScheduleWrite(readRequestCount, writeIntervalRequests int) bool {
	return writeIntervalRequests > 0 && readRequestCount%writeIntervalRequests == 0
}

func feedMixedRatioWork(ctx context.Context, users []string, readChan chan<- string, writeChan chan<- string, writeIntervalRequests int) {
	readRequestCount := 0
	writeRequestCount := 0
	for {
		select {
		case <-ctx.Done():
			log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
			return
		default:
			for _, user := range users {
				select {
				case readChan <- user:
					readRequestCount++
					if shouldScheduleWrite(readRequestCount, writeIntervalRequests) {
						select {
						case writeChan <- user:
							writeRequestCount++
						case <-ctx.Done():
							log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
							return
						}
					}
				case <-ctx.Done():
					log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func feedMixedRateWork(ctx context.Context, users []string, readChan chan<- string, writeChan chan<- string, writeRatePerSecond int) {
	if writeRatePerSecond <= 0 {
		writeRatePerSecond = 1
	}

	readRequestCount := 0
	writeRequestCount := 0
	userIndex := 0
	writeTicker := time.NewTicker(time.Second / time.Duration(writeRatePerSecond))
	defer writeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
			return
		case <-writeTicker.C:
			select {
			case writeChan <- users[userIndex%len(users)]:
				writeRequestCount++
				userIndex++
			case <-ctx.Done():
				log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
				return
			}
		default:
			for _, user := range users {
				select {
				case readChan <- user:
					readRequestCount++
				case <-writeTicker.C:
					select {
					case writeChan <- users[userIndex%len(users)]:
						writeRequestCount++
						userIndex++
					case <-ctx.Done():
						log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
						return
					}
				case <-ctx.Done():
					log.Printf("混合测试结束，共发送读请求 %d 个，写请求 %d 个", readRequestCount, writeRequestCount)
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func worker(ctx context.Context, wg *sync.WaitGroup, userChan <-chan string, config *Config, stats *Stats, scenario string) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case username, ok := <-userChan:
			if !ok {
				return
			}
			executeScenario(username, config, stats, scenario)
		}
	}
}

func executeScenario(username string, config *Config, stats *Stats, scenario string) {
	startTime := time.Now()
	atomic.AddInt64(&stats.TotalRequests, 1)

	client, err := newLDAPClient(config)
	if err != nil {
		log.Printf("连接LDAP失败: %v", err)
		recordFailure(stats, err, startTime)
		return
	}
	defer client.Close()

	connCtx, connCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer connCancel()

	done := make(chan ScenarioResult, 1)
	go func() {
		done <- runScenario(username, config, client, scenario)
	}()

	select {
	case result := <-done:
		if !result.Success {
			log.Printf("场景执行失败 [%s] step=%s: %v", username, result.Step, result.Err)
			recordFailure(stats, fmt.Errorf("%s: %w", result.Step, result.Err), startTime)
			return
		}
	case <-connCtx.Done():
		log.Printf("场景执行超时 [%s]", username)
		recordFailure(stats, fmt.Errorf("场景执行超时"), startTime)
		return
	}

	duration := time.Since(startTime)
	recordSuccess(stats, duration)
}

func newLDAPClient(config *Config) (LDAPClient, error) {
	timeout := time.Duration(config.LDAP.ConnectionTimeoutSeconds) * time.Second
	conn, err := ldap.DialURL(config.LDAP.Address, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(time.Duration(config.LDAP.OperationTimeoutSeconds) * time.Second)
	return &goLDAPClient{conn: conn}, nil
}

func (c *goLDAPClient) Bind(username, password string) error {
	return c.conn.Bind(username, password)
}

func (c *goLDAPClient) Search(req LDAPSearchRequest) (*LDAPSearchResult, error) {
	searchReq := ldap.NewSearchRequest(
		req.BaseDN,
		req.Scope,
		ldap.NeverDerefAliases,
		req.CountLimit,
		0,
		false,
		req.Filter,
		req.Attributes,
		nil,
	)
	result, err := c.conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	entries := make([]LDAPEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		attrs := make(map[string][]string, len(entry.Attributes))
		for _, attr := range entry.Attributes {
			attrs[attr.Name] = append([]string(nil), attr.Values...)
		}
		entries = append(entries, LDAPEntry{
			DN:         entry.DN,
			Attributes: attrs,
		})
	}
	return &LDAPSearchResult{Entries: entries}, nil
}

func (c *goLDAPClient) Modify(req LDAPModifyRequest) error {
	modifyReq := ldap.NewModifyRequest(req.DN, nil)
	switch req.Operation {
	case LDAPModifyAdd:
		modifyReq.Add(req.Attribute, []string{req.Value})
	case LDAPModifyDelete:
		modifyReq.Delete(req.Attribute, []string{req.Value})
	default:
		modifyReq.Replace(req.Attribute, []string{req.Value})
	}
	return c.conn.Modify(modifyReq)
}

func (c *goLDAPClient) Close() {
	c.conn.Close()
}

func runScenario(username string, config *Config, client LDAPClient, scenario string) ScenarioResult {
	userDN := fmt.Sprintf(config.LDAP.UserDNTemplate, username)
	bindDN, bindPassword := bindCredentials(userDN, config, scenario)
	if err := client.Bind(bindDN, bindPassword); err != nil {
		return ScenarioResult{Step: "bind", Err: err}
	}

	switch scenario {
	case ScenarioBind:
		return ScenarioResult{Success: true}
	case ScenarioSearch:
		if _, err := searchCurrentUser(username, config, client, config.LDAP.SearchAttributes); err != nil {
			return ScenarioResult{Step: "search", Err: err}
		}
		return ScenarioResult{Success: true}
	case ScenarioModify:
		value := formatModifyValue(username, config.LDAP.ModifyValueTemplate)
		if err := modifyCurrentUser(username, value, config, client); err != nil {
			return ScenarioResult{Step: "modify", Err: err}
		}
		return ScenarioResult{Success: true}
	case ScenarioBindSearch, ScenarioBindSearchModify:
		if _, err := searchCurrentUser(username, config, client, config.LDAP.SearchAttributes); err != nil {
			return ScenarioResult{Step: "search", Err: err}
		}
		if scenario == ScenarioBindSearch {
			return ScenarioResult{Success: true}
		}
		value := formatModifyValue(username, config.LDAP.ModifyValueTemplate)
		if err := modifyCurrentUser(username, value, config, client); err != nil {
			return ScenarioResult{Step: "modify", Err: err}
		}
		if config.LDAP.VerifyModify {
			attrs := appendUnique(config.LDAP.SearchAttributes, config.LDAP.ModifyAttribute)
			result, err := searchCurrentUser(username, config, client, attrs)
			if err != nil {
				return ScenarioResult{Step: "verify_modify", Err: err}
			}
			if !searchResultContains(result, config.LDAP.ModifyAttribute, value) {
				return ScenarioResult{Step: "verify_modify", Err: fmt.Errorf("%s does not contain %q", config.LDAP.ModifyAttribute, value)}
			}
		}
		return ScenarioResult{Success: true}
	default:
		return ScenarioResult{Step: "scenario", Err: fmt.Errorf("unsupported scenario %q", scenario)}
	}
}

func bindCredentials(userDN string, config *Config, scenario string) (string, string) {
	if usesAdminBind(scenario) {
		adminDN := firstNonEmpty(config.LDAP.AdminBindDN, config.LDAP.BindDN, userDN)
		adminPassword := firstNonEmpty(config.LDAP.AdminPassword, config.LDAP.Password)
		return adminDN, adminPassword
	}
	return userDN, config.LDAP.Password
}

func usesAdminBind(scenario string) bool {
	return scenario == ScenarioSearch ||
		scenario == ScenarioModify ||
		scenario == ScenarioBindSearchModify
}

func searchCurrentUser(username string, config *Config, client LDAPClient, attributes []string) (*LDAPSearchResult, error) {
	req := LDAPSearchRequest{
		BaseDN:     fmt.Sprintf(config.LDAP.SearchBaseTemplate, username),
		Scope:      config.LDAP.SearchScope,
		Filter:     fmt.Sprintf(config.LDAP.SearchFilterTemplate, username),
		Attributes: attributes,
		CountLimit: config.LDAP.SearchCountLimit,
	}
	result, err := client.Search(req)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("未搜索到当前用户 %s", username)
	}
	return result, nil
}

func modifyCurrentUser(username, value string, config *Config, client LDAPClient) error {
	req := LDAPModifyRequest{
		DN:        fmt.Sprintf(config.LDAP.SearchBaseTemplate, username),
		Operation: config.LDAP.ModifyOperation,
		Attribute: config.LDAP.ModifyAttribute,
		Value:     value,
	}
	return client.Modify(req)
}

func formatModifyValue(username, template string) string {
	hasUsername := strings.Contains(template, "%s")
	hasTimestamp := strings.Contains(template, "%d")
	switch {
	case hasUsername && hasTimestamp:
		return fmt.Sprintf(template, username, time.Now().UnixMilli())
	case hasUsername:
		return fmt.Sprintf(template, username)
	case hasTimestamp:
		return fmt.Sprintf(template, time.Now().UnixMilli())
	default:
		return template
	}
}

func searchResultContains(result *LDAPSearchResult, attribute, value string) bool {
	for _, entry := range result.Entries {
		for _, attrValue := range entry.Attributes[attribute] {
			if attrValue == value {
				return true
			}
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	out := append([]string(nil), values...)
	return append(out, value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func joinAttributes(attributes []string) string {
	return strings.Join(attributes, ",")
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

func printMixedStats(readStats, writeStats *Stats) {
	fmt.Println("\n========== 混合压力测试结果 ==========")
	printStatsSection("读场景 bind_search", readStats)
	printStatsSection("写场景 modify", writeStats)

	totalRequests := atomic.LoadInt64(&readStats.TotalRequests) + atomic.LoadInt64(&writeStats.TotalRequests)
	successCount := atomic.LoadInt64(&readStats.SuccessCount) + atomic.LoadInt64(&writeStats.SuccessCount)
	failureCount := atomic.LoadInt64(&readStats.FailureCount) + atomic.LoadInt64(&writeStats.FailureCount)
	testDuration := time.Since(readStats.StartTime).Seconds()
	tps := float64(successCount) / testDuration

	fmt.Println("\n合计:")
	fmt.Printf("测试时长: %.2f 秒\n", testDuration)
	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("成功数: %d\n", successCount)
	fmt.Printf("失败数: %d\n", failureCount)
	fmt.Printf("成功率: %.2f%%\n", percent(successCount, totalRequests))
	fmt.Printf("失败率: %.2f%%\n", percent(failureCount, totalRequests))
	fmt.Printf("TPS (每秒事务数): %.2f\n", tps)
	fmt.Println("======================================")
}

func printStatsSection(name string, stats *Stats) {
	totalRequests := atomic.LoadInt64(&stats.TotalRequests)
	successCount := atomic.LoadInt64(&stats.SuccessCount)
	failureCount := atomic.LoadInt64(&stats.FailureCount)
	totalLatency := atomic.LoadInt64(&stats.TotalLatency)
	minTime := atomic.LoadInt64(&stats.MinTime)
	maxTime := atomic.LoadInt64(&stats.MaxTime)
	testDuration := time.Since(stats.StartTime).Seconds()
	tps := float64(successCount) / testDuration

	fmt.Printf("\n%s:\n", name)
	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("成功数: %d\n", successCount)
	fmt.Printf("失败数: %d\n", failureCount)
	fmt.Printf("成功率: %.2f%%\n", percent(successCount, totalRequests))
	fmt.Printf("失败率: %.2f%%\n", percent(failureCount, totalRequests))
	fmt.Printf("TPS (每秒事务数): %.2f\n", tps)
	if successCount > 0 {
		avgLatency := float64(totalLatency) / float64(successCount)
		fmt.Printf("平均响应时间: %.2f ms\n", avgLatency)
		fmt.Printf("最小响应时间: %d ms\n", minTime)
		fmt.Printf("最大响应时间: %d ms\n", maxTime)
	}
	if len(stats.ErrorDetails) > 0 {
		fmt.Println("错误详情:")
		for errMsg, count := range stats.ErrorDetails {
			fmt.Printf("  %s: %d 次\n", errMsg, count)
		}
	}
}

func percent(count, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(count) / float64(total) * 100
}
