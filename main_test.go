package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	apiVersion := 2
	cfg := configFile{
		Servers: map[string]serverEntry{
			"server1": {
				Protocol:   "https",
				Host:       "panel.example.com",
				Port:       443,
				Token:      "token-1",
				APIVersion: &apiVersion,
			},
		},
	}

	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig returned error: %v", err)
	}

	cfgWithoutVersion := configFile{
		Servers: map[string]serverEntry{
			"server1": {
				Protocol:   "https",
				Host:       "panel.example.com",
				Port:       443,
				Token:      "token-1",
				APIVersion: &apiVersion,
			},
		},
	}
	if err := validateConfig(cfgWithoutVersion); err != nil {
		t.Fatalf("validateConfig should accept config without a version field: %v", err)
	}

	cfg.Servers["server1"] = serverEntry{Protocol: "https", Host: "", Port: 443, Token: "token-1"}
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "缺少有效的 host") {
		t.Fatalf("expected host validation error, got %v", err)
	}
}

func TestValidateConfigAcceptsLegacyURL(t *testing.T) {
	apiVersion := 1
	cfg := configFile{
		Servers: map[string]serverEntry{
			"server1": {
				URL:        "https://panel.example.com:8443",
				Token:      "token-1",
				APIVersion: &apiVersion,
			},
		},
	}

	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validateConfig should accept legacy url config: %v", err)
	}
}

func TestParseLegacyServerURL(t *testing.T) {
	protocol, host, port, err := parseLegacyServerURL("https://panel.example.com:8443")
	if err != nil {
		t.Fatalf("parseLegacyServerURL returned error: %v", err)
	}
	if protocol != "https" || host != "panel.example.com" || port != 8443 {
		t.Fatalf("unexpected parsed result: %s %s %d", protocol, host, port)
	}
}

func TestDefaultConfigFilePathUsesExecutableDir(t *testing.T) {
	exePath, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}
	want := filepath.Join(filepath.Dir(exePath), "config.json")
	if got := defaultConfigFilePath(); got != want {
		t.Fatalf("defaultConfigFilePath() = %q, want %q", got, want)
	}
}

func TestGetAPIPath(t *testing.T) {
	tests := []struct {
		version int
		want    string
		ok      bool
	}{
		{version: 1, want: "/api/v1/websites/ssl/upload", ok: true},
		{version: 2, want: "/api/v2/websites/ssl/upload", ok: true},
		{version: 3, want: "", ok: false},
	}

	for _, tc := range tests {
		got, err := getAPIPath(tc.version)
		if tc.ok && err != nil {
			t.Fatalf("getAPIPath(%d) unexpected error: %v", tc.version, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("getAPIPath(%d) expected error", tc.version)
		}
		if got != tc.want {
			t.Fatalf("getAPIPath(%d) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestShouldUploadCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	now := time.Now()
	oldTime := now.Add(-2 * time.Hour)
	if err := os.Chtimes(certPath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyPath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}

	loc := time.FixedZone("CST", 8*3600)
	shouldUpload, err := shouldUploadCertificate(certPath, keyPath, false, 3600, loc)
	if err != nil {
		t.Fatalf("shouldUploadCertificate returned error: %v", err)
	}
	if shouldUpload {
		t.Fatalf("expected upload to be skipped for stale files")
	}

	futureTime := now.Add(2 * time.Hour)
	if err := os.Chtimes(certPath, futureTime, futureTime); err != nil {
		t.Fatalf("chtimes cert future: %v", err)
	}
	shouldUpload, err = shouldUploadCertificate(certPath, keyPath, false, 3600, loc)
	if err != nil {
		t.Fatalf("shouldUploadCertificate returned error: %v", err)
	}
	if !shouldUpload {
		t.Fatalf("expected upload for future timestamp")
	}
}

func TestBuildPayload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	certContent := "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"
	keyContent := "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(certPath, []byte(certContent), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	payload, err := buildPayload(certPath, keyPath, 123, "同步更新 @2026-09-03 12:00:00 CST (UTC+08:00)")
	if err != nil {
		t.Fatalf("buildPayload returned error: %v", err)
	}

	var parsed struct {
		Type        string `json:"type"`
		SSLID       int64  `json:"sslID"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privateKey"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if parsed.Type != "paste" || parsed.SSLID != 123 || parsed.Certificate != certContent || parsed.PrivateKey != keyContent {
		t.Fatalf("unexpected payload content: %+v", parsed)
	}
	if !strings.Contains(parsed.Description, "同步更新 @") {
		t.Fatalf("unexpected description: %q", parsed.Description)
	}
}

func TestPerformUpload(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte("cert-content"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key-content"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v2/websites/ssl/upload" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		timestamp := r.Header.Get("1Panel-Timestamp")
		if timestamp == "" {
			t.Fatal("missing timestamp header")
		}
		expectedToken := signToken("api-token", mustParseInt64(t, timestamp))
		if got := r.Header.Get("1Panel-Token"); got != expectedToken {
			t.Fatalf("unexpected token header: got %s want %s", got, expectedToken)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %s", got)
		}

		var payload struct {
			Type        string `json:"type"`
			SSLID       int64  `json:"sslID"`
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"privateKey"`
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.Type != "paste" || payload.SSLID != 456 || payload.Certificate != "cert-content" || payload.PrivateKey != "key-content" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
		if !strings.HasPrefix(payload.Description, "同步更新 @") {
			t.Fatalf("unexpected description: %q", payload.Description)
		}

		_, _ = w.Write([]byte(`{"code":200,"message":"ok"}`))
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	host, portText, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	serverConfig := resolvedServer{
		Name:       "server1",
		Protocol:   "http",
		Host:       host,
		Port:       port,
		Token:      "api-token",
		APIVersion: 2,
	}

	resp, err := performUpload(serverConfig, 456, certPath, keyPath, time.UTC, time.Unix(1_700_000_000, 0), false)
	if err != nil {
		t.Fatalf("performUpload returned error: %v", err)
	}
	if resp.Code != 200 || resp.HTTPStatus != http.StatusOK {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRequestTargetUsesServerIP(t *testing.T) {
	serverConfig := resolvedServer{
		Name:       "server1",
		Protocol:   "https",
		Host:       "panel.example.com",
		Port:       8443,
		ServerIP:   "10.0.0.23",
		Token:      "api-token",
		APIVersion: 2,
	}

	if got := serverConfig.requestURL("/api/v2/websites/ssl/upload"); got != "https://10.0.0.23:8443/api/v2/websites/ssl/upload" {
		t.Fatalf("unexpected request url: %s", got)
	}
	if got := serverConfig.hostHeader(); got != "panel.example.com:8443" {
		t.Fatalf("unexpected host header: %s", got)
	}
	if got := serverConfig.hostNameForTLS(); got != "panel.example.com" {
		t.Fatalf("unexpected tls host name: %s", got)
	}
}

func TestAttemptUploadRetriesOnTLSFailure(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte("cert-content"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key-content"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	requestCount := 0
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_, _ = w.Write([]byte(`{"code":200,"message":"ok"}`))
	}))
	defer tlsServer.Close()

	parsedTLSServerURL, err := url.Parse(tlsServer.URL)
	if err != nil {
		t.Fatalf("parse tls server url: %v", err)
	}
	tlsHost, tlsPortText, err := net.SplitHostPort(parsedTLSServerURL.Host)
	if err != nil {
		t.Fatalf("split tls host port: %v", err)
	}
	tlsPort, err := strconv.Atoi(tlsPortText)
	if err != nil {
		t.Fatalf("parse tls port: %v", err)
	}

	serverConfig := resolvedServer{
		Name:       "server1",
		Protocol:   "https",
		Host:       tlsHost,
		Port:       tlsPort,
		Token:      "api-token",
		APIVersion: 2,
	}

	if err := attemptUpload(serverConfig, 789, certPath, keyPath, time.UTC); err != nil {
		t.Fatalf("attemptUpload returned error: %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("expected one successful retry request, got %d", requestCount)
	}
}

func mustParseInt64(t *testing.T, value string) int64 {
	t.Helper()
	ts, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("parse int64 %q: %v", value, err)
	}
	return ts
}
