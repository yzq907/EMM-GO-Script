package inventory

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPAMClientLoginAndPagingReuseAuthentication(t *testing.T) {
	var mu sync.Mutex
	pages := make([]int, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]string{"token": "runtime-token"}})
			return
		}
		if r.Header.Get("X-Auth-Token") != "runtime-token" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("pageIndex"))
		mu.Lock()
		pages = append(pages, page)
		mu.Unlock()
		items := []RemoteAsset{}
		if page == 1 {
			items = []RemoteAsset{{ID: "a1", Name: "one"}, {ID: "a2", Name: "two"}}
		} else if page == 2 {
			items = []RemoteAsset{{ID: "a3", Name: "three"}}
		}
		json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"items": items, "total": 3}})
	}))
	defer server.Close()

	client, err := NewPAMClient(server.URL, PAMOptions{PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Login(context.Background(), "user", "secret"); err != nil {
		t.Fatal(err)
	}
	assets, err := client.ListAssets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 3 || strings.Join([]string{assets[0].Name, assets[1].Name, assets[2].Name}, ",") != "one,two,three" {
		t.Fatalf("assets = %#v", assets)
	}
	if got := strings.Trim(strings.Join(intStrings(pages), ","), ","); got != "1,2" {
		t.Fatalf("pages = %v", pages)
	}
}

func TestPAMClientImportUsesCSVContractAndRetriesTransientFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]string{"token": "runtime-token"}})
			return
		}
		if r.URL.Path == "/login/crypto-key" {
			http.Error(w, "legacy mock has no crypto-key", http.StatusNotFound)
			return
		}
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path != "/assets/import" || r.Method != http.MethodPost {
			http.Error(w, "wrong endpoint", http.StatusNotFound)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing file", http.StatusBadRequest)
			return
		}
		defer file.Close()
		rows, err := csv.NewReader(file).ReadAll()
		if err != nil || len(rows) != 2 {
			http.Error(w, "bad csv", http.StatusBadRequest)
			return
		}
		if got := rows[0]; len(got) != 15 || got[0] != "资产名称" || got[14] != "描述" {
			http.Error(w, "bad header", http.StatusBadRequest)
			return
		}
		if rows[1][0] != "pamlt-va-test" || rows[1][3] != "ssh" || rows[1][8] != "root" || rows[1][9] != "runtime-password" {
			http.Error(w, "bad row", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]int{"success": 1}})
	}))
	defer server.Close()

	client, err := NewPAMClient(server.URL, PAMOptions{MaxRetries: 1, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Login(context.Background(), "user", "secret"); err != nil {
		t.Fatal(err)
	}
	asset := Asset{Name: "pamlt-va-test", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22}
	err = client.ImportAssets(context.Background(), []Asset{asset}, ImportCredentials{
		Group: "default", Department: "LEAGSOFT / 未知部门", AccountType: "custom", Username: "root", Password: "runtime-password", Tags: "pam-loadtest|virtual-assets",
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestPAMClientSanitizesImportErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]string{"token": "runtime-token"}})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `password=runtime-password token=runtime-token`)
	}))
	defer server.Close()
	client, _ := NewPAMClient(server.URL, PAMOptions{})
	_ = client.Login(context.Background(), "user", "secret")
	err := client.ImportAssets(context.Background(), []Asset{{Name: GeneratedPrefix + "ssh", Marker: GeneratedMarker, IP: "10.200.0.1", Protocol: "ssh", Port: 22}}, ImportCredentials{Password: "runtime-password"})
	if err == nil || strings.Contains(err.Error(), "runtime-password") || strings.Contains(err.Error(), "runtime-token") {
		t.Fatalf("unsanitized error: %v", err)
	}
}

func TestPAMClientEnrichesAssetWithItsUniqueImportedAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]string{"token": "runtime-token"}})
		case "/assets/paging":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"items": []RemoteAsset{{ID: "asset-one", Name: GeneratedPrefix + "one", DBType: "-", AccountCount: 1}}, "total": 1}})
		case "/resource-accounts/paging":
			json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"items": []map[string]string{{"id": "account-one", "assetId": "asset-one"}}, "total": 1}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, _ := NewPAMClient(server.URL, PAMOptions{})
	if err := client.Login(context.Background(), "user", "secret"); err != nil {
		t.Fatal(err)
	}
	assets, err := client.ListAssets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].DefaultAccountID != "account-one" {
		t.Fatalf("assets = %+v", assets)
	}
}

func intStrings(values []int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strconv.Itoa(value)
	}
	return out
}
