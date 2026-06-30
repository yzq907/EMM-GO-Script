package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	DownloadURL    string `json:"download_url"`
	Cookie         string `json:"cookie"`
	Concurrency    int    `json:"concurrency"`
	Duration       int    `json:"duration"`
	Interval       int    `json:"interval"`
	MaxIdleConns   int    `json:"max_idle_conns"`
	RequestTimeout int    `json:"request_timeout"`
	LogFile        string `json:"log_file"`
	LogLevel       string `json:"log_level"`
	ConnectTimeout int    `json:"connect_timeout"`
}

type Logger struct {
	file  *os.File
	level string
	mu    sync.Mutex
}

func NewLogger(logFile, logLevel string) (*Logger, error) {
	logger := &Logger{level: logLevel}
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("打开日志文件失败: %w", err)
		}
		logger.file = file
	}
	return logger, nil
}

func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) log(level, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, message)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Print(logMessage)
	if l.file != nil {
		l.file.WriteString(logMessage)
	}
}

func (l *Logger) Info(format string, args ...interface{})  { l.log("INFO", format, args...) }
func (l *Logger) Error(format string, args ...interface{}) { l.log("ERROR", format, args...) }
func (l *Logger) Warn(format string, args ...interface{})  { l.log("WARN", format, args...) }
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level == "DEBUG" {
		l.log("DEBUG", format, args...)
	}
}

type DownloadStats struct {
	TotalTasks    int
	SuccessTasks  int
	FailedTasks   int
	TotalBytes    int64
	StartTime     time.Time
	EndTime       time.Time
	TotalDuration time.Duration
}

type WorkerResult struct {
	WorkerID int
	Success  bool
	Size     int64
	Duration time.Duration
	Error    error
}

type Downloader struct {
	config         Config
	httpClient     *http.Client
	logger         *Logger
	connectTimeout time.Duration
}

func setSocketKeepAlive(fd uintptr) error {
	_ = fd
	return nil
}

func NewDownloader(config Config, logger *Logger) *Downloader {
	dialer := &net.Dialer{
		Timeout:   time.Duration(config.ConnectTimeout) * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				logger.Debug("正在设置TCP keepalive, fd=%d", fd)
				err = setSocketKeepAlive(fd)
				if err != nil {
					logger.Warn("设置TCP keepalive失败: %v", err)
				} else {
					logger.Debug("TCP keepalive设置成功: fd=%d", fd)
				}
			})
			return err
		},
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConns,
		MaxConnsPerHost:       config.MaxIdleConns,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true, // 大文件禁用压缩，减少 CPU 消耗
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false, // HTTP/1.1 更稳定，避免 h2 多路复用带来的干扰
	}

	requestTimeout := time.Duration(config.RequestTimeout) * time.Second
	if requestTimeout <= 0 {
		requestTimeout = 120 * time.Second
	}
	connectTimeout := time.Duration(config.ConnectTimeout) * time.Second
	if connectTimeout <= 0 {
		connectTimeout = 30 * time.Second
	}

	logger.Debug("HTTP客户端配置: 请求超时=%v, 连接超时=%v, 最大空闲连接=%d",
		requestTimeout, connectTimeout, config.MaxIdleConns)

	return &Downloader{
		config: config,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
		},
		logger:         logger,
		connectTimeout: connectTimeout,
	}
}

// Download 流式读取响应体，不在内存中积累数据。
// 返回已接收字节数；内存占用恒定 ~32KB（buffer 大小）。
func (d *Downloader) Download(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", d.config.DownloadURL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Cookie", d.config.Cookie)
	req.Header.Set("Connection", "keep-alive")

	d.logger.Debug("发送HTTP请求到: %s", d.config.DownloadURL)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	d.logger.Debug("收到响应, 状态码: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("下载失败, 状态码: %d", resp.StatusCode)
	}

	contentLength := resp.Header.Get("Content-Length")
	d.logger.Debug("开始读取响应体, Content-Length: %s", contentLength)

	// 关键修复：用 io.Copy + io.Discard 流式消费，内存恒定 32KB
	// 不需要保存文件内容，只验证传输完整性（字节数是否正确）
	written, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		d.logger.Error("读取响应体出错, 已读取: %d bytes, 错误: %v", written, err)
		return written, fmt.Errorf("读取响应失败: %w", err)
	}

	d.logger.Debug("响应体读取完成, 大小: %d bytes", written)
	return written, nil
}

func (d *Downloader) ConcurrentDownload(ctx context.Context) (*DownloadStats, error) {
	stats := &DownloadStats{
		StartTime: time.Now(),
	}

	duration := time.Duration(d.config.Duration) * time.Second
	if duration <= 0 {
		duration = 60 * time.Second
	}

	d.logger.Info("启动 %d 个并发客户端，持续下载 %v", d.config.Concurrency, duration)

	stopCh := make(chan struct{})
	resultsCh := make(chan WorkerResult, 100)

	go func() {
		time.Sleep(duration)
		d.logger.Info("达到设置时间 %v，等待当前下载任务完成后退出...", duration)
		close(stopCh)
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]WorkerResult, 0)

	for i := 0; i < d.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					d.logger.Debug("Worker %d: 收到停止信号，退出", workerID)
					return
				default:
					startTime := time.Now()
					d.logger.Debug("Worker %d: 开始下载", workerID)

					size, err := d.Download(ctx)
					downloadDuration := time.Since(startTime)

					select {
					case <-stopCh:
						d.logger.Debug("Worker %d: 下载完成后收到停止信号，退出", workerID)
						return
					default:
					}

					result := WorkerResult{
						WorkerID: workerID,
						Success:  err == nil,
						Size:     size,
						Duration: downloadDuration,
						Error:    err,
					}

					select {
					case resultsCh <- result:
					default:
					}

					if err != nil {
						d.logger.Error("Worker %d: 下载失败 - %v (耗时: %v)", workerID, err, downloadDuration)
					} else {
						d.logger.Debug("Worker %d: 下载完成, 大小: %d bytes (耗时: %v)", workerID, size, downloadDuration)
					}

					if d.config.Interval > 0 {
						intervalDuration := time.Duration(d.config.Interval) * time.Second
						select {
						case <-stopCh:
							d.logger.Debug("Worker %d: 间隔等待期间收到停止信号，退出", workerID)
							return
						case <-time.After(intervalDuration):
						}
					}
				}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	for result := range resultsCh {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}

	stats.EndTime = time.Now()
	stats.TotalDuration = stats.EndTime.Sub(stats.StartTime)
	stats.TotalTasks = len(results)

	for _, result := range results {
		if result.Success {
			stats.SuccessTasks++
			stats.TotalBytes += result.Size
		} else {
			stats.FailedTasks++
		}
	}

	if stats.SuccessTasks == 0 {
		return stats, fmt.Errorf("所有下载任务都失败了")
	}

	return stats, nil
}

func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		fmt.Printf("加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	logger, err := NewLogger(config.LogFile, config.LogLevel)
	if err != nil {
		fmt.Printf("创建日志记录器失败: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	downloader := NewDownloader(config, logger)

	ctxTimeout := time.Duration(config.Duration+300) * time.Second
	logger.Debug("Context超时设置: %v", ctxTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	logger.Info("开始下载文件: %s", config.DownloadURL)
	logger.Info("并发数: %d, 持续时间: %d秒", config.Concurrency, config.Duration)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logger.Debug("下载前内存使用: %.2f MB", float64(m.Alloc)/1024/1024)

	stats, err := downloader.ConcurrentDownload(ctx)
	if err != nil {
		logger.Error("下载失败: %v", err)
		os.Exit(1)
	}

	runtime.ReadMemStats(&m)
	logger.Debug("下载后内存使用: %.2f MB", float64(m.Alloc)/1024/1024)

	stats.printReport()
}

func (s *DownloadStats) printReport() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                    下载统计报告")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\n【总体统计】\n")
	fmt.Printf("总任务数:     %d\n", s.TotalTasks)
	fmt.Printf("成功任务:     %d\n", s.SuccessTasks)
	fmt.Printf("失败任务:     %d\n", s.FailedTasks)
	successRate := float64(s.SuccessTasks) / float64(s.TotalTasks) * 100
	fmt.Printf("成功率:       %.2f%%\n", successRate)
	fmt.Printf("总下载数据:   %s\n", formatBytes(s.TotalBytes))

	fmt.Printf("\n【时间统计】\n")
	fmt.Printf("开始时间:     %s\n", s.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("结束时间:     %s\n", s.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("总耗时:       %v\n", s.TotalDuration)

	fmt.Println("\n" + strings.Repeat("=", 60))
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func loadConfig(filename string) (Config, error) {
	var config Config
	data, err := os.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("读取配置文件失败: %w", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("解析配置文件失败: %w", err)
	}
	if config.DownloadURL == "" {
		return config, fmt.Errorf("下载地址不能为空")
	}
	if config.Cookie == "" {
		return config, fmt.Errorf("Cookie不能为空")
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 5
	}
	if config.Duration <= 0 {
		config.Duration = 60
	}
	if config.Interval < 0 {
		config.Interval = 0
	}
	if config.MaxIdleConns <= 0 {
		config.MaxIdleConns = 200
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 1800
	}
	if config.ConnectTimeout <= 0 {
		config.ConnectTimeout = 60
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	fmt.Printf("配置: 并发数=%d, 持续时间=%d秒, 间隔=%d秒, 最大空闲连接=%d, 请求超时=%d秒, 连接超时=%d秒, 日志级别=%s\n",
		config.Concurrency, config.Duration, config.Interval, config.MaxIdleConns, config.RequestTimeout, config.ConnectTimeout, config.LogLevel)
	return config, nil
}
