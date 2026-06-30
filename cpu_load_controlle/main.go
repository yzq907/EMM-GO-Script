package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
)

type Config struct {
	CpuPercent float64 `json:"cpu_percent"`
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func burnCPU(targetPercent float64) {
	interval := 100 * time.Millisecond
	workTime := time.Duration(float64(interval) * targetPercent / 100)
	sleepTime := interval - workTime

	for {
		start := time.Now()
		for time.Since(start) < workTime {
			_ = 1 + 1
		}
		time.Sleep(sleepTime)
	}
}

func main() {
	cfg, err := loadConfig("config.json")
	if err != nil {
		fmt.Printf("读取配置文件失败: %v\n", err)
		return
	}

	cpus := runtime.NumCPU()
	perCore := cfg.CpuPercent

	fmt.Printf("启动 %d 个 goroutine，每核 %.2f%%\n", cpus, perCore)

	for i := 0; i < cpus; i++ {
		go burnCPU(perCore)
	}

	select {} // 阻塞主线程
}
