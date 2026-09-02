package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"pam-loadtest/internal/config"
	"pam-loadtest/internal/distributed"
	"pam-loadtest/internal/inventory"
	"pam-loadtest/internal/runreport"
)

func Run(args []string, out, errOut io.Writer) int {
	return RunContext(context.Background(), args, out, errOut)
}

func RunContext(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: pam-loadtest <validate|run> <scenario.yaml>")
		return 2
	}
	if args[0] == "run" {
		if len(args) != 2 {
			fmt.Fprintln(errOut, "usage: pam-loadtest run <scenario.yaml>")
			return 2
		}
		workers, err := envInt("PAM_BROWSER_WORKERS", 1)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		perWorker, err := envInt("PAM_BROWSER_SESSIONS_PER_WORKER", 50)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		opts := LocalOptions{MetricsListen: os.Getenv("PAM_METRICS_LISTEN"), NodeExecutable: os.Getenv("PAM_NODE_EXECUTABLE"), WorkerScript: os.Getenv("PAM_BROWSER_WORKER_SCRIPT"), BrowserWorkers: workers, SessionsPerWorker: perWorker}
		var report runreport.Report
		if os.Getenv("PAM_ASSET_MANIFEST") != "" {
			report, err = RunLocalReport(ctx, args[1], opts)
		} else {
			err = RunLocal(ctx, args[1], opts)
		}
		if err != nil {
			fmt.Fprintf(errOut, "run failed: %v\n", err)
			return 1
		}
		if report.Totals.Planned > 0 {
			if err := writeRunReport(out, report); err != nil {
				fmt.Fprintf(errOut, "write report: %v\n", err)
				return 1
			}
		} else {
			fmt.Fprintln(out, "run completed")
		}
		return 0
	}
	if args[0] == "inventory" {
		if len(args) < 2 {
			fmt.Fprintln(errOut, "usage: pam-loadtest inventory <plan|apply|verify> ...")
			return 2
		}
		if args[1] == "apply" {
			return runInventoryApply(ctx, args[2:], out, errOut)
		}
		if args[1] == "verify" {
			return runInventoryVerify(ctx, args[2:], out, errOut)
		}
		if args[1] != "plan" {
			fmt.Fprintln(errOut, "usage: pam-loadtest inventory plan <output.json>")
			return 2
		}
		profile, output, ok := inventoryPlanArgs(args[2:])
		if !ok {
			fmt.Fprintln(errOut, "usage: pam-loadtest inventory plan [--profile=base|extension|combined|capacity] <output.json>")
			return 2
		}
		var assets []inventory.Asset
		var err error
		switch profile {
		case "base":
			assets, err = inventory.Plan(inventory.DefaultSpec())
		case "extension":
			assets, err = inventory.Plan(inventory.ExtensionSpec())
		case "combined":
			assets, err = inventory.CombinedPlan()
		case "capacity":
			assets, err = inventory.CapacityPlan()
		default:
			fmt.Fprintf(errOut, "unknown inventory profile %s\n", profile)
			return 2
		}
		if err != nil {
			fmt.Fprintf(errOut, "inventory plan failed: %v\n", err)
			return 1
		}
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err == nil {
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(assets)
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
		}
		if err != nil {
			fmt.Fprintf(errOut, "write inventory plan: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "wrote %d planned assets\n", len(assets))
		return 0
	}
	if args[0] == "agent" {
		if len(args) != 2 {
			fmt.Fprintln(errOut, "usage: pam-loadtest agent <scenario.yaml>")
			return 2
		}
		token := os.Getenv("PAM_AGENT_TOKEN")
		if token == "" {
			fmt.Fprintln(errOut, "PAM_AGENT_TOKEN is required")
			return 1
		}
		capacity, err := envInt("PAM_AGENT_CAPACITY", 250)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		directCapacity, err := agentDirectCapacity(capacity)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		workers, err := envInt("PAM_BROWSER_WORKERS", 1)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		perWorker, err := envInt("PAM_BROWSER_SESSIONS_PER_WORKER", 50)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		listen := os.Getenv("PAM_AGENT_LISTEN")
		if listen == "" {
			listen = ":9443"
		}
		err = RunAgent(ctx, args[1], listen, token, capacity, LocalOptions{MetricsListen: os.Getenv("PAM_METRICS_LISTEN"), NodeExecutable: os.Getenv("PAM_NODE_EXECUTABLE"), WorkerScript: os.Getenv("PAM_BROWSER_WORKER_SCRIPT"), BrowserWorkers: workers, SessionsPerWorker: perWorker, DirectCapacity: directCapacity})
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(errOut, "agent failed: %v\n", err)
			return 1
		}
		return 0
	}
	if args[0] == "agent-health" {
		if len(args) != 2 {
			fmt.Fprintln(errOut, "usage: pam-loadtest agent-health <host:port>")
			return 2
		}
		token := os.Getenv("PAM_AGENT_TOKEN")
		if token == "" {
			fmt.Fprintln(errOut, "PAM_AGENT_TOKEN is required")
			return 1
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		client, err := distributed.DialAgent(ctx, args[1], func(ctx context.Context, target string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", target)
		}, token)
		if err != nil {
			fmt.Fprintf(errOut, "agent health failed: %v\n", err)
			return 1
		}
		defer client.Close()
		health, err := client.Health(ctx)
		if err != nil {
			fmt.Fprintf(errOut, "agent health failed: %v\n", err)
			return 1
		}
		if err := json.NewEncoder(out).Encode(health); err != nil {
			fmt.Fprintf(errOut, "write agent health: %v\n", err)
			return 1
		}
		return 0
	}
	if args[0] == "controller" {
		if len(args) != 2 {
			fmt.Fprintln(errOut, "usage: pam-loadtest controller <scenario.yaml>")
			return 2
		}
		raw := os.Getenv("PAM_AGENTS")
		if strings.TrimSpace(raw) == "" {
			fmt.Fprintln(errOut, "PAM_AGENTS must list at least one agent")
			return 1
		}
		report, err := RunController(ctx, args[1], strings.Split(raw, ","), os.Getenv("PAM_AGENT_TOKEN"))
		return finishControllerRun(out, errOut, report, err)
	}
	if len(args) != 2 || args[0] != "validate" {
		fmt.Fprintln(errOut, "usage: pam-loadtest <validate|run> <scenario.yaml>")
		return 2
	}
	cfg, err := config.Load(args[1])
	if err == nil {
		_, err = cfg.Expand()
	}
	if err != nil {
		fmt.Fprintf(errOut, "invalid scenario: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "valid scenario %s: %d sessions, ramp %s, hold %s\n", cfg.Name, cfg.Total, cfg.Ramp, cfg.Hold)
	return 0
}

func finishControllerRun(out, errOut io.Writer, report runreport.Report, runErr error) int {
	if report.Version != 0 {
		if err := writeRunReport(out, report); err != nil {
			fmt.Fprintf(errOut, "write report: %v\n", err)
			return 1
		}
	}
	if runErr != nil {
		fmt.Fprintf(errOut, "controller failed: %v\n", runErr)
		return 1
	}
	return 0
}

func inventoryPlanArgs(args []string) (profile, output string, ok bool) {
	profile = "base"
	for _, arg := range args {
		if strings.HasPrefix(arg, "--profile=") {
			profile = strings.TrimPrefix(arg, "--profile=")
		} else if output == "" {
			output = arg
		} else {
			return "", "", false
		}
	}
	return profile, output, output != ""
}

func writeRunReport(out io.Writer, report runreport.Report) error {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

func runInventoryApply(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(errOut, "usage: pam-loadtest inventory apply <plan.json> [--execute] [--limit=N]")
		return 2
	}
	options := inventory.ApplyOptions{}
	for _, arg := range args[1:] {
		switch {
		case arg == "--execute":
			options.Execute = true
		case strings.HasPrefix(arg, "--limit="):
			limit, err := strconv.Atoi(strings.TrimPrefix(arg, "--limit="))
			if err != nil || limit < 1 {
				fmt.Fprintln(errOut, "--limit must be a positive integer")
				return 2
			}
			options.Limit = limit
		default:
			fmt.Fprintf(errOut, "unknown inventory apply option %s\n", arg)
			return 2
		}
	}
	desired, err := loadInventoryPlan(args[0])
	if err != nil {
		fmt.Fprintf(errOut, "load inventory plan: %v\n", err)
		return 1
	}
	client, err := inventoryClient(ctx)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	if options.Execute {
		options.Credentials = inventory.ImportCredentials{
			Group:       envDefault("PAM_ASSET_GROUP", "default"),
			Department:  envDefault("PAM_ASSET_DEPARTMENT", "LEAGSOFT / 未知部门"),
			AccountType: envDefault("PAM_ASSET_ACCOUNT_TYPE", "custom"),
			Username:    os.Getenv("PAM_ASSET_USERNAME"),
			Password:    os.Getenv("PAM_ASSET_PASSWORD"),
			Tags:        envDefault("PAM_ASSET_TAGS", "pam-loadtest|virtual-assets"),
		}
		if options.Credentials.Username == "" || options.Credentials.Password == "" {
			fmt.Fprintln(errOut, "PAM_ASSET_USERNAME and PAM_ASSET_PASSWORD are required with --execute")
			return 1
		}
	}
	report, err := inventory.Apply(ctx, client, desired, options)
	if err != nil {
		fmt.Fprintf(errOut, "inventory apply failed: %v\n", err)
		return 1
	}
	mode := "dry-run"
	if options.Execute {
		mode = "execute"
	}
	fmt.Fprintf(out, "%s desired=%d existing=%d pending=%d created=%d\n", mode, report.Desired, report.Existing, report.Pending, report.Created)
	return 0
}

func runInventoryVerify(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(errOut, "usage: pam-loadtest inventory verify <plan.json> <manifest.json>")
		return 2
	}
	desired, err := loadInventoryPlan(args[0])
	if err != nil {
		fmt.Fprintf(errOut, "load inventory plan: %v\n", err)
		return 1
	}
	client, err := inventoryClient(ctx)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	report, err := inventory.Apply(ctx, client, desired, inventory.ApplyOptions{})
	if err != nil || report.Existing != len(desired) || report.Pending != 0 {
		fmt.Fprintf(errOut, "inventory verification failed: existing=%d pending=%d error=%v\n", report.Existing, report.Pending, err)
		return 1
	}
	remote, err := client.ListAssets(ctx)
	if err != nil {
		fmt.Fprintf(errOut, "inventory verification failed: %v\n", err)
		return 1
	}
	markerSet := make(map[string]struct{})
	for _, asset := range desired {
		markerSet[asset.Marker] = struct{}{}
	}
	markers := make([]string, 0, len(markerSet))
	for marker := range markerSet {
		markers = append(markers, marker)
	}
	manifest, err := inventory.BuildManifestForMarkers(remote, markers)
	if err != nil || len(manifest.Assets) != len(desired) {
		fmt.Fprintf(errOut, "inventory manifest verification failed: generated=%d expected=%d error=%v\n", len(manifest.Assets), len(desired), err)
		return 1
	}
	if err := inventory.WriteManifest(args[1], manifest); err != nil {
		fmt.Fprintf(errOut, "write inventory manifest: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "verified %d generated assets and accounts\n", len(manifest.Assets))
	return 0
}

func loadInventoryPlan(path string) ([]inventory.Asset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var desired []inventory.Asset
	if err := json.NewDecoder(io.LimitReader(file, 16<<20)).Decode(&desired); err != nil {
		return nil, err
	}
	if len(desired) == 0 {
		return nil, fmt.Errorf("inventory plan is empty")
	}
	return desired, nil
}

func inventoryClient(ctx context.Context) (*inventory.PAMClient, error) {
	baseURL, username, password := os.Getenv("PAM_BASE_URL"), os.Getenv("PAM_USERNAME"), os.Getenv("PAM_PASSWORD")
	if baseURL == "" || username == "" || password == "" {
		return nil, fmt.Errorf("PAM_BASE_URL, PAM_USERNAME, and PAM_PASSWORD are required")
	}
	client, err := inventory.NewPAMClient(baseURL, inventory.PAMOptions{MaxRetries: 2})
	if err != nil {
		return nil, err
	}
	if err := client.Login(ctx, username, password); err != nil {
		return nil, err
	}
	return client, nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return n, nil
}

func agentDirectCapacity(fallback int) (int, error) {
	return envInt("PAM_AGENT_DIRECT_CAPACITY", fallback)
}
