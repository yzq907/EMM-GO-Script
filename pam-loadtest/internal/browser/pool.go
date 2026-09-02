package browser

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Job struct {
	ID          int
	Protocol    string
	URL         string
	AssetID     string
	AccountID   string
	LoginURL    string
	Username    string
	Password    string
	Cookies     []Cookie
	OnConnected func(time.Duration)
}
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url"`
}
type Result struct {
	JobID              int
	Heartbeats         int64
	LastActivity       time.Time
	PrepareLatency     time.Duration
	EditorReadyLatency time.Duration
}
type Client interface {
	Run(context.Context, Job) (Result, error)
	Close() error
}
type Factory func(slot int) (Client, error)

type Pool struct {
	mu                sync.Mutex
	closed            bool
	available         chan int
	clients           []Client
	factory           Factory
	sessionsPerWorker int
}

func NewPool(size int, factory Factory) *Pool {
	return NewPoolWithCapacity(size, 1, factory)
}

func NewPoolWithCapacity(size, sessionsPerWorker int, factory Factory) *Pool {
	if size < 1 {
		size = 1
	}
	if sessionsPerWorker < 1 {
		sessionsPerWorker = 1
	}
	p := &Pool{available: make(chan int, size*sessionsPerWorker), clients: make([]Client, size), factory: factory, sessionsPerWorker: sessionsPerWorker}
	for i := 0; i < size; i++ {
		for n := 0; n < sessionsPerWorker; n++ {
			p.available <- i
		}
	}
	for i := range p.clients {
		client, err := factory(i)
		if err == nil {
			p.clients[i] = client
		}
	}
	return p
}

func (p *Pool) Run(ctx context.Context, job Job) (Result, error) {
	if job.Protocol != "rdp" && job.Protocol != "vnc" && job.Protocol != "web" && job.Protocol != "mysql" {
		return Result{}, fmt.Errorf("unsupported browser protocol %q", job.Protocol)
	}
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return Result{}, fmt.Errorf("browser pool is closed")
	}
	var slot int
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case slot = <-p.available:
	}
	defer func() { p.available <- slot }()
	client := p.clients[slot]
	if client == nil {
		return Result{}, fmt.Errorf("browser worker %d unavailable", slot)
	}
	result, err := client.Run(ctx, job)
	if err == nil || ctx.Err() != nil || p.sessionsPerWorker > 1 {
		return result, err
	}
	_ = client.Close()
	replacement, createErr := p.factory(slot)
	if createErr != nil {
		p.clients[slot] = nil
		return result, fmt.Errorf("restart browser worker %d: %w", slot, createErr)
	}
	p.clients[slot] = replacement
	return replacement.Run(ctx, job)
}

func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	var first error
	for _, client := range p.clients {
		if client != nil {
			if err := client.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
