package inventory

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"time"

	"pam-loadtest/internal/sm2login"
)

type PAMOptions struct {
	HTTPClient *http.Client
	PageSize   int
	MaxRetries int
	RetryDelay time.Duration
}

type PAMClient struct {
	base       *url.URL
	http       *http.Client
	token      string
	pageSize   int
	maxRetries int
	retryDelay time.Duration
}

type RemoteAsset struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	IP               string `json:"ip"`
	Protocol         string `json:"protocol"`
	DBType           string `json:"dbType"`
	Port             int    `json:"port"`
	AccountCount     int    `json:"accountCount"`
	DefaultAccountID string `json:"defaultAccountId"`
}

type remoteAccount struct {
	ID      string `json:"id"`
	AssetID string `json:"assetId"`
}

type ImportCredentials struct {
	Group        string
	Department   string
	AccountType  string
	Username     string
	Password     string
	DatabaseName string
	Tags         string
}

func NewPAMClient(baseURL string, options PAMOptions) (*PAMClient, error) {
	base, err := url.Parse(baseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("invalid PAM base URL")
	}
	client := options.HTTPClient
	if client == nil {
		jar, _ := cookiejar.New(nil)
		client = &http.Client{Timeout: 30 * time.Second, Jar: jar}
	}
	if options.PageSize < 1 {
		options.PageSize = 200
	}
	if options.RetryDelay <= 0 {
		options.RetryDelay = 250 * time.Millisecond
	}
	return &PAMClient{base: base, http: client, pageSize: options.PageSize, maxRetries: options.MaxRetries, retryDelay: options.RetryDelay}, nil
}

func (c *PAMClient) Login(ctx context.Context, username, password string) error {
	// Newer SGP-PAM builds require the password to be SM2-encrypted.
	// Try that first and fall back to the legacy plaintext flow.
	raw, err := c.sm2Login(ctx, username, password)
	if err != nil {
		body, marshalErr := json.Marshal(map[string]string{"username": username, "password": password})
		if marshalErr != nil {
			return marshalErr
		}
		raw, err = c.do(ctx, http.MethodPost, "/login", "application/json", body)
		if err != nil {
			return err
		}
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			Token       string `json:"token"`
			AccessToken string `json:"accessToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.Code != 1 {
		return fmt.Errorf("PAM login rejected")
	}
	c.token = response.Data.Token
	if c.token == "" {
		c.token = response.Data.AccessToken
	}
	return nil
}

// sm2Login performs the SM2-encrypted password login flow used by newer
// SGP-PAM builds. It returns an error when the crypto-key endpoint is
// unavailable so the caller can fall back to the legacy plaintext login.
func (c *PAMClient) sm2Login(ctx context.Context, username, password string) ([]byte, error) {
	raw, err := c.do(ctx, http.MethodGet, "/login/crypto-key", "", nil)
	if err != nil {
		return nil, err
	}
	var keyResp struct {
		Code int `json:"code"`
		Data struct {
			PublicKey  string `json:"publicKey"`
			CipherMode string `json:"cipherMode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &keyResp); err != nil || keyResp.Code != 1 || keyResp.Data.PublicKey == "" {
		return nil, fmt.Errorf("PAM login crypto-key unavailable")
	}
	encrypted, err := sm2login.EncryptPassword(password, keyResp.Data.PublicKey, keyResp.Data.CipherMode)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]any{
		"username":          username,
		"remember":          false,
		"encryptedPassword": encrypted,
	})
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodPost, "/login", "application/json", payload)
}

func (c *PAMClient) ListAssets(ctx context.Context) ([]RemoteAsset, error) {
	var all []RemoteAsset
	for page := 1; ; page++ {
		path := fmt.Sprintf("/assets/paging?pageIndex=%d&pageSize=%d&field=&order=", page, c.pageSize)
		raw, err := c.do(ctx, http.MethodGet, path, "", nil)
		if err != nil {
			return nil, err
		}
		var response struct {
			Code int `json:"code"`
			Data struct {
				Items []RemoteAsset `json:"items"`
				Total int           `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &response); err != nil || response.Code != 1 {
			return nil, fmt.Errorf("decode PAM asset page %d", page)
		}
		all = append(all, response.Data.Items...)
		if len(all) >= response.Data.Total || len(response.Data.Items) == 0 {
			break
		}
	}
	needsAccounts := false
	for _, asset := range all {
		if asset.AccountCount == 1 && asset.DefaultAccountID == "" {
			needsAccounts = true
			break
		}
	}
	if !needsAccounts {
		return all, nil
	}
	accounts, err := c.listAccounts(ctx)
	if err != nil {
		return nil, err
	}
	byAsset := make(map[string][]string)
	for _, account := range accounts {
		byAsset[account.AssetID] = append(byAsset[account.AssetID], account.ID)
	}
	for i := range all {
		if all[i].DefaultAccountID == "" && len(byAsset[all[i].ID]) == 1 {
			all[i].DefaultAccountID = byAsset[all[i].ID][0]
		}
	}
	return all, nil
}

func (c *PAMClient) listAccounts(ctx context.Context) ([]remoteAccount, error) {
	var all []remoteAccount
	for page := 1; ; page++ {
		path := fmt.Sprintf("/resource-accounts/paging?pageIndex=%d&pageSize=%d", page, c.pageSize)
		raw, err := c.do(ctx, http.MethodGet, path, "", nil)
		if err != nil {
			return nil, err
		}
		var response struct {
			Code int `json:"code"`
			Data struct {
				Items []remoteAccount `json:"items"`
				Total int             `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &response); err != nil || response.Code != 1 {
			return nil, fmt.Errorf("decode PAM account page %d", page)
		}
		all = append(all, response.Data.Items...)
		if len(all) >= response.Data.Total || len(response.Data.Items) == 0 {
			return all, nil
		}
	}
}

func (c *PAMClient) ImportAssets(ctx context.Context, assets []Asset, credentials ImportCredentials) error {
	if len(assets) == 0 {
		return nil
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "assets.csv")
	if err != nil {
		return fmt.Errorf("build PAM asset import")
	}
	csvWriter := csv.NewWriter(part)
	header := []string{"资产名称", "资产分组名称", "部门", "协议", "数据库类型", "主机地址", "端口", "账号类型", "用户名", "密码", "私钥", "私钥口令", "数据库名", "标签", "描述"}
	_ = csvWriter.Write(header)
	for _, asset := range assets {
		_ = csvWriter.Write([]string{asset.Name, credentials.Group, credentials.Department, asset.Protocol, asset.DBType, asset.IP, strconv.Itoa(asset.Port), credentials.AccountType, credentials.Username, credentials.Password, "", "", credentials.DatabaseName, credentials.Tags, asset.Marker})
	}
	csvWriter.Flush()
	if csvWriter.Error() != nil || writer.Close() != nil {
		return fmt.Errorf("build PAM asset import")
	}
	_, err = c.do(ctx, http.MethodPost, "/assets/import", writer.FormDataContentType(), body.Bytes())
	return err
}

func (c *PAMClient) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		reference, err := url.Parse(path)
		if err != nil {
			return nil, fmt.Errorf("build PAM request")
		}
		target := c.base.ResolveReference(reference)
		req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build PAM request")
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if c.token != "" {
			req.Header.Set("X-Auth-Token", c.token)
		}
		response, err := c.http.Do(req)
		if err == nil {
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
			response.Body.Close()
			if token := response.Header.Get("X-Auth-Token"); token != "" {
				c.token = token
			}
			if readErr == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
				var envelope struct {
					Code int `json:"code"`
				}
				if json.Unmarshal(raw, &envelope) == nil && envelope.Code != 0 && envelope.Code != 1 {
					return nil, fmt.Errorf("PAM %s %s rejected request", method, safePath(path))
				}
				return raw, nil
			}
			if response.StatusCode != http.StatusTooManyRequests && response.StatusCode < 500 {
				return nil, fmt.Errorf("PAM %s %s returned %d", method, safePath(path), response.StatusCode)
			}
		}
		if attempt >= c.maxRetries {
			return nil, fmt.Errorf("PAM %s %s failed after %d attempt(s)", method, safePath(path), attempt+1)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.retryDelay):
		}
	}
}

func safePath(path string) string {
	if parsed, err := url.Parse(path); err == nil {
		return parsed.Path
	}
	return "[invalid-path]"
}
