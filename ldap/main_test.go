package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeLDAPClient struct {
	ops []string
}

func (f *fakeLDAPClient) Bind(username, password string) error {
	f.ops = append(f.ops, "bind:"+username+":"+password)
	return nil
}

func (f *fakeLDAPClient) Search(req LDAPSearchRequest) (*LDAPSearchResult, error) {
	f.ops = append(f.ops, "search:"+req.BaseDN+":"+req.Filter+":"+joinAttributes(req.Attributes))
	return &LDAPSearchResult{
		Entries: []LDAPEntry{
			{
				DN: req.BaseDN,
				Attributes: map[string][]string{
					"cn":          {"u00_000001"},
					"description": {"go-write-u00_000001-123456789"},
				},
			},
		},
	}, nil
}

func (f *fakeLDAPClient) Modify(req LDAPModifyRequest) error {
	f.ops = append(f.ops, "modify:"+req.DN+":"+req.Attribute+":"+req.Value)
	return nil
}

func (f *fakeLDAPClient) Close() {
	f.ops = append(f.ops, "close")
}

func TestLoadConfigDefaultsToBindScenario(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
ldap:
  address: "ldap://127.0.0.1:389"
  password: "Password123!"
  user_dn_template: "CN=%s,OU=Users,DC=example,DC=com"
stress_test:
  concurrent_users: 1
  duration_seconds: 1
  user_data_file: "data.csv"
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.StressTest.Scenario != ScenarioBind {
		t.Fatalf("scenario = %q, want %q", cfg.StressTest.Scenario, ScenarioBind)
	}
	if cfg.LDAP.SearchScope != LDAPScopeBaseObject {
		t.Fatalf("search scope = %d, want %d", cfg.LDAP.SearchScope, LDAPScopeBaseObject)
	}
	if cfg.LDAP.ModifyOperation != LDAPModifyReplace {
		t.Fatalf("modify operation = %q, want %q", cfg.LDAP.ModifyOperation, LDAPModifyReplace)
	}
}

func TestRunScenarioBindSearchModifyUsesAdminBindAndVerifiesWrite(t *testing.T) {
	cfg := &Config{}
	cfg.LDAP.BindDN = "administrator"
	cfg.LDAP.Password = "Emm@2025"
	cfg.LDAP.UserDNTemplate = "CN=%s,OU=ou00_team,DC=dev,DC=local"
	cfg.LDAP.SearchBaseTemplate = "CN=%s,OU=ou00_team,DC=dev,DC=local"
	cfg.LDAP.SearchFilterTemplate = "(&(objectClass=person)(cn=%s))"
	cfg.LDAP.SearchAttributes = []string{"cn", "distinguishedName", "objectClass"}
	cfg.LDAP.SearchScope = LDAPScopeBaseObject
	cfg.LDAP.SearchCountLimit = 1
	cfg.LDAP.ModifyAttribute = "description"
	cfg.LDAP.ModifyOperation = LDAPModifyReplace
	cfg.LDAP.ModifyValueTemplate = "go-write-%s-123456789"
	cfg.LDAP.VerifyModify = true

	client := &fakeLDAPClient{}
	result := runScenario("u00_000001", cfg, client, ScenarioBindSearchModify)
	if !result.Success {
		t.Fatalf("runScenario failed: step=%s err=%v", result.Step, result.Err)
	}

	want := []string{
		"bind:administrator:Emm@2025",
		"search:CN=u00_000001,OU=ou00_team,DC=dev,DC=local:(&(objectClass=person)(cn=u00_000001)):cn,distinguishedName,objectClass",
		"modify:CN=u00_000001,OU=ou00_team,DC=dev,DC=local:description:go-write-u00_000001-123456789",
		"search:CN=u00_000001,OU=ou00_team,DC=dev,DC=local:(&(objectClass=person)(cn=u00_000001)):cn,distinguishedName,objectClass,description",
	}
	if len(client.ops) != len(want) {
		t.Fatalf("ops length = %d, want %d: %#v", len(client.ops), len(want), client.ops)
	}
	for i := range want {
		if client.ops[i] != want[i] {
			t.Fatalf("ops[%d] = %q, want %q", i, client.ops[i], want[i])
		}
	}
}

func TestRunScenarioSearchOnlyUsesAdminBindAndSearch(t *testing.T) {
	cfg := &Config{}
	cfg.LDAP.BindDN = "administrator"
	cfg.LDAP.Password = "Emm@2025"
	cfg.LDAP.UserDNTemplate = "CN=%s,OU=ou00_team,DC=dev,DC=local"
	cfg.LDAP.SearchBaseTemplate = "CN=%s,OU=ou00_team,DC=dev,DC=local"
	cfg.LDAP.SearchFilterTemplate = "(&(objectClass=person)(cn=%s))"
	cfg.LDAP.SearchAttributes = []string{"cn", "distinguishedName", "objectClass"}
	cfg.LDAP.SearchScope = LDAPScopeBaseObject
	cfg.LDAP.SearchCountLimit = 1

	client := &fakeLDAPClient{}
	result := runScenario("u00_000001", cfg, client, ScenarioSearch)
	if !result.Success {
		t.Fatalf("runScenario failed: step=%s err=%v", result.Step, result.Err)
	}

	want := []string{
		"bind:administrator:Emm@2025",
		"search:CN=u00_000001,OU=ou00_team,DC=dev,DC=local:(&(objectClass=person)(cn=u00_000001)):cn,distinguishedName,objectClass",
	}
	if len(client.ops) != len(want) {
		t.Fatalf("ops length = %d, want %d: %#v", len(client.ops), len(want), client.ops)
	}
	for i := range want {
		if client.ops[i] != want[i] {
			t.Fatalf("ops[%d] = %q, want %q", i, client.ops[i], want[i])
		}
	}
}

func TestRunScenarioModifyOnlyUsesAdminBindAndModify(t *testing.T) {
	cfg := &Config{}
	cfg.LDAP.BindDN = "administrator"
	cfg.LDAP.Password = "Emm@2025"
	cfg.LDAP.UserDNTemplate = "CN=%s,OU=ou00_team,DC=dev,DC=local"
	cfg.LDAP.SearchBaseTemplate = "CN=%s,OU=ou00_team,DC=dev,DC=local"
	cfg.LDAP.ModifyAttribute = "description"
	cfg.LDAP.ModifyOperation = LDAPModifyReplace
	cfg.LDAP.ModifyValueTemplate = "go-write-%s-123456789"
	cfg.LDAP.VerifyModify = true

	client := &fakeLDAPClient{}
	result := runScenario("u00_000001", cfg, client, ScenarioModify)
	if !result.Success {
		t.Fatalf("runScenario failed: step=%s err=%v", result.Step, result.Err)
	}

	want := []string{
		"bind:administrator:Emm@2025",
		"modify:CN=u00_000001,OU=ou00_team,DC=dev,DC=local:description:go-write-u00_000001-123456789",
	}
	if len(client.ops) != len(want) {
		t.Fatalf("ops length = %d, want %d: %#v", len(client.ops), len(want), client.ops)
	}
	for i := range want {
		if client.ops[i] != want[i] {
			t.Fatalf("ops[%d] = %q, want %q", i, client.ops[i], want[i])
		}
	}
}

func TestFormatModifyValueSupportsDefaultUsernameAndLiteralTemplates(t *testing.T) {
	if got := formatModifyValue("u00_000001", "fixed-description"); got != "fixed-description" {
		t.Fatalf("literal template = %q, want fixed-description", got)
	}

	if got := formatModifyValue("u00_000001", "write-%s"); got != "write-u00_000001" {
		t.Fatalf("username template = %q, want write-u00_000001", got)
	}

	got := formatModifyValue("u00_000001", "write-%s-%d")
	if !strings.HasPrefix(got, "write-u00_000001-") {
		t.Fatalf("timestamp template = %q, want prefix write-u00_000001-", got)
	}
}

func TestLoadConfigDefaultsMixedWorkload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
ldap:
  address: "ldap://127.0.0.1:389"
  password: "Password123!"
  user_dn_template: "CN=%s,OU=Users,DC=example,DC=com"
stress_test:
  concurrent_users: 20
  duration_seconds: 1
  user_data_file: "data.csv"
  scenario: "mixed"
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.StressTest.ReadConcurrentUsers != 20 {
		t.Fatalf("read workers = %d, want 20", cfg.StressTest.ReadConcurrentUsers)
	}
	if cfg.StressTest.WriteConcurrentUsers != 1 {
		t.Fatalf("write workers = %d, want 1", cfg.StressTest.WriteConcurrentUsers)
	}
	if cfg.StressTest.WriteIntervalRequests != 1000 {
		t.Fatalf("write interval = %d, want 1000", cfg.StressTest.WriteIntervalRequests)
	}
	if cfg.StressTest.WriteSchedule != WriteScheduleRatio {
		t.Fatalf("write schedule = %q, want %q", cfg.StressTest.WriteSchedule, WriteScheduleRatio)
	}
}

func TestShouldScheduleWriteEveryConfiguredReadInterval(t *testing.T) {
	var writes []int
	for reads := 1; reads <= 2500; reads++ {
		if shouldScheduleWrite(reads, 1000) {
			writes = append(writes, reads)
		}
	}

	want := []int{1000, 2000}
	if len(writes) != len(want) {
		t.Fatalf("writes = %#v, want %#v", writes, want)
	}
	for i := range want {
		if writes[i] != want[i] {
			t.Fatalf("writes[%d] = %d, want %d", i, writes[i], want[i])
		}
	}
}

func TestLoadConfigRateScheduleUsesGlobalWriteRate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`
ldap:
  address: "ldap://127.0.0.1:389"
  password: "Password123!"
  user_dn_template: "CN=%s,OU=Users,DC=example,DC=com"
stress_test:
  concurrent_users: 20
  duration_seconds: 1
  user_data_file: "data.csv"
  scenario: "mixed"
  write_concurrent_users: 5
  write_schedule: "rate"
  write_rate_per_second: 5
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig returned error: %v", err)
	}

	if cfg.StressTest.WriteSchedule != WriteScheduleRate {
		t.Fatalf("write schedule = %q, want %q", cfg.StressTest.WriteSchedule, WriteScheduleRate)
	}
	if cfg.StressTest.WriteConcurrentUsers != 5 {
		t.Fatalf("write workers = %d, want 5", cfg.StressTest.WriteConcurrentUsers)
	}
	if cfg.StressTest.WriteRatePerSecond != 5 {
		t.Fatalf("write rate = %d, want global rate 5", cfg.StressTest.WriteRatePerSecond)
	}
}
