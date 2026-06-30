package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Redis RedisConfig `yaml:"redis"`
	App   AppConfig   `yaml:"app"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	Mode     string `yaml:"mode"`
}

type AppConfig struct {
	TargetBytes     int64  `yaml:"target_bytes"`
	EstimatedPerKey int64  `yaml:"estimated_per_key"`
	KeyPrefix       string `yaml:"key_prefix"`
	BatchSize       int    `yaml:"batch_size"`
	Concurrent      int    `yaml:"concurrent"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.App.BatchSize == 0 {
		cfg.App.BatchSize = 100
	}
	if cfg.App.Concurrent == 0 {
		cfg.App.Concurrent = 4
	}
	if cfg.Redis.Mode == "" {
		cfg.Redis.Mode = "standalone"
	}

	return &cfg, nil
}

func connectRedis(cfg *Config) redis.Cmdable {
	if cfg.Redis.Mode == "cluster" {
		return redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    []string{cfg.Redis.Addr},
			Password: cfg.Redis.Password,
		})
	}

	return redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		DB:       cfg.Redis.DB,
		Password: cfg.Redis.Password,
		PoolSize: cfg.App.Concurrent * 2,
	})
}

func checkCommand(cfg *Config) {
	ctx := context.Background()
	rdb := connectRedis(cfg)

	var dbsize int64
	var err error

	if cfg.Redis.Mode == "cluster" {
		var size int64 = 0
		clusterClient := rdb.(*redis.ClusterClient)
		err = clusterClient.ForEachMaster(ctx, func(ctx context.Context, master *redis.Client) error {
			n, err := master.DBSize(ctx).Result()
			if err != nil {
				return err
			}
			size += n
			return nil
		})
		dbsize = size
	} else {
		client := rdb.(*redis.Client)
		dbsize, err = client.DBSize(ctx).Result()
	}

	if err != nil {
		fmt.Printf("❌ 检查失败: %v\n", err)
		os.Exit(1)
	}

	if cfg.Redis.Mode == "cluster" {
		fmt.Printf("========== 集群模式检查 ==========\n")
		fmt.Printf("当前集群总 key 数量: %d\n", dbsize)
	} else {
		fmt.Printf("========== DB%d 状态检查 ==========\n", cfg.Redis.DB)
		fmt.Printf("当前 key 数量: %d\n", dbsize)

		if dbsize > 0 {
			fmt.Printf("\n⚠️  DB%d 中已有数据 (%d 个 key)\n", cfg.Redis.DB, dbsize)
			fmt.Println("   建议：先清理现有数据再写入测试数据")
		} else {
			fmt.Printf("\n✅ DB%d 是空的，可以安全写入\n", cfg.Redis.DB)
		}
	}

	var prefixCount int
	if cfg.Redis.Mode == "cluster" {
		clusterClient := rdb.(*redis.ClusterClient)
		err = clusterClient.ForEachMaster(ctx, func(ctx context.Context, master *redis.Client) error {
			count, err := scanKeys(ctx, master, cfg.App.KeyPrefix+"*")
			if err != nil {
				return err
			}
			prefixCount += count
			return nil
		})
	} else {
		client := rdb.(*redis.Client)
		count, err := scanKeys(ctx, client, cfg.App.KeyPrefix+"*")
		if err != nil {
			fmt.Printf("❌ 检查前缀 key 失败: %v\n", err)
			return
		}
		prefixCount = count
	}

	if err != nil && err.Error() != "ERR this instance has cluster support disabled" {
		fmt.Printf("❌ 检查前缀 key 失败: %v\n", err)
	}

	if prefixCount > 0 {
		fmt.Printf("\n⚠️  找到 %d 个以 '%s' 开头的测试 key\n", prefixCount, cfg.App.KeyPrefix)
		fmt.Println("   这些是之前写入的测试数据")
	} else {
		fmt.Printf("\n✅ 没有找到以 '%s' 开头的测试 key\n", cfg.App.KeyPrefix)
	}
	fmt.Println("===================================")
}

func generateData(size int) string {
	return strings.Repeat("x", size)
}

func scanKeys(ctx context.Context, rdb *redis.Client, pattern string) (int, error) {
	var count int
	var cursor uint64
	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return count, err
		}
		count += len(keys)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return count, nil
}

func scanKeysToList(ctx context.Context, rdb *redis.Client, pattern string) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		result, nextCursor, err := rdb.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return keys, err
		}
		keys = append(keys, result...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

func writeWorker(ctx context.Context, rdb redis.Cmdable, cfg *Config, targetBytes int64, doneChan chan<- int64) {
	var localWritten int64 = 0
	var localCount int64 = 0
	keyPrefix := cfg.App.KeyPrefix
	estimatedPerKey := cfg.App.EstimatedPerKey

	for localWritten < targetBytes {
		key := fmt.Sprintf("%s%s", keyPrefix, uuid.New().String())
		dataSize := int(estimatedPerKey) - 100

		var err error
		if cfg.Redis.Mode == "cluster" {
			clusterClient := rdb.(*redis.ClusterClient)
			err = clusterClient.HSet(ctx, key, map[string]interface{}{
				"f1": generateData(dataSize),
				"f2": uuid.New().String(),
				"f3": "1234567890",
				"f4": "abcdefghijklmnopqrstuvwxyz",
				"f5": "test-data",
			}).Err()
		} else {
			pipe := rdb.(*redis.Client).Pipeline()
			pipe.HSet(ctx, key, map[string]interface{}{
				"f1": generateData(dataSize),
				"f2": uuid.New().String(),
				"f3": "1234567890",
				"f4": "abcdefghijklmnopqrstuvwxyz",
				"f5": "test-data",
			})
			_, err = pipe.Exec(ctx)
		}

		if err != nil && err != redis.Nil {
			fmt.Printf("❌ 写入失败: %v\n", err)
			os.Exit(1)
		}

		localWritten += estimatedPerKey
		localCount++

		if localCount%10000 == 0 {
			fmt.Printf("当前 worker 已写入 %d 条\n", localCount)
		}
	}

	doneChan <- localCount
}

func writeCommand(cfg *Config) {
	ctx := context.Background()
	rdb := connectRedis(cfg)

	var prefixCount int
	var err error

	if cfg.Redis.Mode == "cluster" {
		clusterClient := rdb.(*redis.ClusterClient)
		err = clusterClient.ForEachMaster(ctx, func(ctx context.Context, master *redis.Client) error {
			count, err := scanKeys(ctx, master, cfg.App.KeyPrefix+"*")
			if err != nil {
				return err
			}
			prefixCount += count
			return nil
		})
	} else {
		client := rdb.(*redis.Client)
		dbsize, err := client.DBSize(ctx).Result()
		if err != nil {
			fmt.Printf("❌ 检查失败: %v\n", err)
			os.Exit(1)
		}
		if dbsize > 0 {
			fmt.Printf("❌ DB%d 中已有 %d 个 key，请先清理再写入\n", cfg.Redis.DB, dbsize)
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Printf("❌ 检查失败: %v\n", err)
		os.Exit(1)
	}

	if prefixCount > 0 {
		fmt.Printf("❌ 已存在 %d 个以 '%s' 开头的 key，请先清理再写入\n", prefixCount, cfg.App.KeyPrefix)
		os.Exit(1)
	}

	targetBytes := cfg.App.TargetBytes / int64(cfg.App.Concurrent)
	concurrent := cfg.App.Concurrent

	fmt.Printf("开始向 DB%d 写入数据，目标 %.2f GB...\n", cfg.Redis.DB, float64(cfg.App.TargetBytes)/1024/1024/1024)
	fmt.Printf("使用 %d 个并发，每个并发目标 %.2f GB...\n", concurrent, float64(targetBytes)/1024/1024/1024)

	var totalCount int64 = 0
	var wg sync.WaitGroup
	doneChan := make(chan int64, concurrent)

	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeWorker(ctx, rdb, cfg, targetBytes, doneChan)
		}()
	}

	go func() {
		wg.Wait()
		close(doneChan)
	}()

	ticker := 0
	for count := range doneChan {
		atomic.AddInt64(&totalCount, count)
		ticker++
		if ticker%10 == 0 {
			fmt.Printf("已写入 %d 条，约 %.2f MB\n",
				totalCount, float64(atomic.LoadInt64(&totalCount)*cfg.App.EstimatedPerKey)/1024/1024)
		}
	}

	fmt.Println("✅ 写入完成")
	fmt.Printf("总计写入 %d 条 key\n", totalCount)
}

func cleanCommand(cfg *Config) {
	ctx := context.Background()
	rdb := connectRedis(cfg)

	var keys []string
	var err error

	if cfg.Redis.Mode == "cluster" {
		clusterClient := rdb.(*redis.ClusterClient)
		err = clusterClient.ForEachMaster(ctx, func(ctx context.Context, master *redis.Client) error {
			k, err := scanKeysToList(ctx, master, cfg.App.KeyPrefix+"*")
			if err != nil {
				return err
			}
			keys = append(keys, k...)
			return nil
		})
	} else {
		client := rdb.(*redis.Client)
		keys, err = scanKeysToList(ctx, client, cfg.App.KeyPrefix+"*")
	}

	if err != nil && err.Error() != "ERR this instance has cluster support disabled" {
		fmt.Printf("❌ 查询失败: %v\n", err)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Printf("✅ 没有找到以 '%s' 开头的测试 key\n", cfg.App.KeyPrefix)
		return
	}

	fmt.Printf("找到 %d 个测试 key，准备删除...\n", len(keys))

	if cfg.Redis.Mode == "cluster" {
		clusterClient := rdb.(*redis.ClusterClient)
		deleted := 0
		for _, key := range keys {
			err = clusterClient.Del(ctx, key).Err()
			if err != nil {
				fmt.Printf("❌ 删除失败: %v\n", err)
				os.Exit(1)
			}
			deleted++
			if deleted%1000 == 0 {
				fmt.Printf("已删除 %d/%d 个 key\n", deleted, len(keys))
			}
		}
	} else {
		const batchSize = 1000
		for i := 0; i < len(keys); i += batchSize {
			end := i + batchSize
			if end > len(keys) {
				end = len(keys)
			}
			batch := keys[i:end]

			client := rdb.(*redis.Client)
			err = client.Del(ctx, batch...).Err()

			if err != nil {
				fmt.Printf("❌ 删除失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("已删除 %d/%d 个 key\n", end, len(keys))
		}
	}

	fmt.Println("✅ 清理完成")
}

func printUsage() {
	fmt.Println("Redis 测试数据工具")
	fmt.Println("")
	fmt.Println("用法:")
	fmt.Println("  go run main.go check    检查 DB 中是否有数据")
	fmt.Println("  go run main.go write    写入测试数据")
	fmt.Println("  go run main.go clean    清理测试数据")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  go run main.go check    # 先检查 DB 状态")
	fmt.Println("  go run main.go write    # 写入测试数据")
	fmt.Println("  go run main.go clean    # 清理测试数据")
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	cfg, err := loadConfig("config.yaml")
	if err != nil {
		fmt.Printf("❌ 加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	switch command {
	case "check":
		checkCommand(cfg)
	case "write":
		writeCommand(cfg)
	case "clean":
		cleanCommand(cfg)
	default:
		fmt.Printf("未知命令: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}
