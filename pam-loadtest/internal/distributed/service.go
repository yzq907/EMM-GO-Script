package distributed

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"pam-loadtest/internal/runreport"
)

type jsonCodec struct{}

func (jsonCodec) Name() string                    { return "json" }
func (jsonCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func init()                                       { encoding.RegisterCodec(jsonCodec{}) }

type HealthRequest struct{}
type Capabilities struct {
	Version         string   `json:"version"`
	Capacity        int      `json:"capacity"`
	DirectCapacity  int      `json:"direct_capacity"`
	BrowserCapacity int      `json:"browser_capacity"`
	DirectProtocols []string `json:"direct_protocols"`
}
type HealthResponse struct {
	Capacity     int          `json:"capacity"`
	Capabilities Capabilities `json:"capabilities"`
}
type WireJob struct {
	ID        int    `json:"id"`
	Protocol  string `json:"protocol"`
	Mode      string `json:"mode"`
	AssetID   string `json:"asset_id"`
	AccountID string `json:"account_id"`
}
type RunRequest struct {
	RunID                          string           `json:"run_id"`
	PAMToken                       string           `json:"pam_token,omitempty"`
	PAMCookies                     []PAMCookie      `json:"pam_cookies,omitempty"`
	RampNanos                      int64            `json:"ramp_nanos"`
	HoldNanos                      int64            `json:"hold_nanos"`
	SSHActivityIntervalNanos       int64            `json:"ssh_activity_interval_nanos"`
	SSHActivityMode                string           `json:"ssh_activity_mode"`
	GraphicalActivityIntervalNanos map[string]int64 `json:"graphical_activity_interval_nanos,omitempty"`
	ContinueOnErrors               bool             `json:"continue_on_errors"`
	ConnectionOnly                 bool             `json:"connection_only"`
	ConnectRetries                 int              `json:"connect_retries"`
	Seed                           int64            `json:"seed"`
	Jobs                           []WireJob        `json:"jobs"`
}
type PAMCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
}
type RunResponse struct {
	RunID    string    `json:"run_id"`
	Accepted int       `json:"accepted"`
	Status   RunStatus `json:"status"`
}

type RunStatus string

const (
	Pending   RunStatus = "pending"
	Running   RunStatus = "running"
	Completed RunStatus = "completed"
	Failed    RunStatus = "failed"
	Cancelled RunStatus = "cancelled"
)

type StatusRequest struct {
	RunID string `json:"run_id"`
}
type StatusResponse struct {
	RunID  string            `json:"run_id"`
	Status RunStatus         `json:"status"`
	Report *runreport.Report `json:"report,omitempty"`
	Error  string            `json:"error,omitempty"`
}
type CancelRequest struct {
	RunID string `json:"run_id"`
}
type CancelResponse struct {
	RunID  string    `json:"run_id"`
	Status RunStatus `json:"status"`
}

type AgentOperations interface {
	Start(context.Context, RunRequest) (RunResponse, error)
	Status(context.Context, StatusRequest) (StatusResponse, error)
	Cancel(context.Context, CancelRequest) (CancelResponse, error)
}
type agentService struct {
	capabilities Capabilities
	operations   AgentOperations
}

func NewAgentServer(token string, capacity int, operations AgentOperations) *grpc.Server {
	return NewAgentServerWithCapabilities(token, Capabilities{Version: "legacy", Capacity: capacity, DirectCapacity: capacity, BrowserCapacity: capacity, DirectProtocols: []string{"ssh", "rdp", "vnc", "web", "mysql"}}, operations)
}

func NewAgentServerWithCapabilities(token string, capabilities Capabilities, operations AgentOperations) *grpc.Server {
	auth := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		values := md.Get("authorization")
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte("Bearer "+token)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "agent authentication failed")
		}
		return next(ctx, req)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(auth))
	svc := &agentService{capabilities: capabilities, operations: operations}
	s.RegisterService(&agentServiceDesc, svc)
	return s
}

func healthHandler(s any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(HealthRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	invoke := func(context.Context, any) (any, error) {
		capabilities := s.(*agentService).capabilities
		return &HealthResponse{Capacity: capabilities.Capacity, Capabilities: capabilities}, nil
	}
	if interceptor == nil {
		return invoke(ctx, req)
	}
	return interceptor(ctx, req, &grpc.UnaryServerInfo{Server: s, FullMethod: "/pamloadtest.Agent/Health"}, invoke)
}
func startHandler(s any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(RunRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	invoke := func(ctx context.Context, request any) (any, error) {
		r := request.(*RunRequest)
		response, err := s.(*agentService).operations.Start(ctx, *r)
		if err != nil {
			return nil, err
		}
		return &response, nil
	}
	if interceptor == nil {
		return invoke(ctx, req)
	}
	return interceptor(ctx, req, &grpc.UnaryServerInfo{Server: s, FullMethod: "/pamloadtest.Agent/Start"}, invoke)
}

func statusHandler(s any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(StatusRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	invoke := func(ctx context.Context, request any) (any, error) {
		response, err := s.(*agentService).operations.Status(ctx, *request.(*StatusRequest))
		if err != nil {
			return nil, err
		}
		return &response, nil
	}
	if interceptor == nil {
		return invoke(ctx, req)
	}
	return interceptor(ctx, req, &grpc.UnaryServerInfo{Server: s, FullMethod: "/pamloadtest.Agent/Status"}, invoke)
}

func cancelHandler(s any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(CancelRequest)
	if err := dec(req); err != nil {
		return nil, err
	}
	invoke := func(ctx context.Context, request any) (any, error) {
		response, err := s.(*agentService).operations.Cancel(ctx, *request.(*CancelRequest))
		if err != nil {
			return nil, err
		}
		return &response, nil
	}
	if interceptor == nil {
		return invoke(ctx, req)
	}
	return interceptor(ctx, req, &grpc.UnaryServerInfo{Server: s, FullMethod: "/pamloadtest.Agent/Cancel"}, invoke)
}

var agentServiceDesc = grpc.ServiceDesc{ServiceName: "pamloadtest.Agent", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{{MethodName: "Health", Handler: healthHandler}, {MethodName: "Start", Handler: startHandler}, {MethodName: "Status", Handler: statusHandler}, {MethodName: "Cancel", Handler: cancelHandler}}}

type AgentClient struct {
	conn  *grpc.ClientConn
	token string
}

func DialAgent(ctx context.Context, target string, dialer func(context.Context, string) (net.Conn, error), token string) (*AgentClient, error) {
	if !strings.Contains(target, "://") {
		target = "passthrough:///" + target
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
	if err != nil {
		return nil, fmt.Errorf("dial agent: %w", err)
	}
	return &AgentClient{conn: conn, token: token}, nil
}
func (c *AgentClient) context(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
}
func (c *AgentClient) Health(ctx context.Context) (HealthResponse, error) {
	var out HealthResponse
	err := c.conn.Invoke(c.context(ctx), "/pamloadtest.Agent/Health", &HealthRequest{}, &out)
	return out, err
}
func (c *AgentClient) Start(ctx context.Context, in RunRequest) (RunResponse, error) {
	var out RunResponse
	err := c.conn.Invoke(c.context(ctx), "/pamloadtest.Agent/Start", &in, &out)
	return out, err
}
func (c *AgentClient) Status(ctx context.Context, in StatusRequest) (StatusResponse, error) {
	var out StatusResponse
	err := c.conn.Invoke(c.context(ctx), "/pamloadtest.Agent/Status", &in, &out)
	return out, err
}
func (c *AgentClient) Cancel(ctx context.Context, in CancelRequest) (CancelResponse, error) {
	var out CancelResponse
	err := c.conn.Invoke(c.context(ctx), "/pamloadtest.Agent/Cancel", &in, &out)
	return out, err
}
func (c *AgentClient) Close() error { return c.conn.Close() }
