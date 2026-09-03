package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultCertFile        = "./fullchain.pem"
	defaultKeyFile         = "./privkey.pem"
	defaultAutoWindow      = 5
	defaultSemiAutoWindow  = 86400
	defaultMaxRetries      = 8
	defaultRetryInterval   = 15
	supportedConfigVersion = 1
	defaultAPIVersion      = 2

	requestConnectTimeout    = 10 * time.Second
	requestTotalTimeout      = 60 * time.Second
	requestTLSHandshakeLimit = 10 * time.Second
)

type configFile struct {
	Version int                    `json:"version"`
	Servers map[string]serverEntry `json:"servers"`
}

type serverEntry struct {
	URL        string `json:"url"`
	Token      string `json:"token"`
	APIVersion *int   `json:"api_version"`
}

type resolvedServer struct {
	Name       string
	URL        string
	Token      string
	APIVersion int
}

type options struct {
	sslIDs         []string
	servers        []string
	certFile       string
	keyFile        string
	configFile     string
	force          bool
	semiAutoWindow int
	maxRetries     int
	retryInterval  int
}

type uploadResponse struct {
	HTTPStatus int
	Code       int
	Message    string
	Insecure   bool
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts, err := parseOptions(args)
	if err != nil {
		fatalf("%v", err)
		return 1
	}

	config, err := loadConfig(opts.configFile)
	if err != nil {
		fatalf("%v", err)
		return 1
	}

	if err := validateConfig(config); err != nil {
		fatalf("%v", err)
		return 1
	}

	if err := checkCertificateFiles(opts.certFile, opts.keyFile); err != nil {
		fatalf("%v", err)
		return 1
	}

	window := defaultAutoWindow
	if opts.certFile != defaultCertFile || opts.keyFile != defaultKeyFile {
		window = opts.semiAutoWindow
		logf("半自动模式激活 | 时间窗口: %d 秒", window)
	}

	loc := displayLocation()
	shouldUpload, err := shouldUploadCertificate(opts.certFile, opts.keyFile, opts.force, window, loc)
	if err != nil {
		fatalf("%v", err)
		return 1
	}
	if !shouldUpload {
		return 0
	}

	if len(opts.sslIDs) != len(opts.servers) {
		fatalf("SSL ID 数量（%d）与服务器数量（%d）不匹配", len(opts.sslIDs), len(opts.servers))
		return 1
	}

	overallExitCode := 0
	for i := range opts.servers {
		serverName := strings.TrimSpace(opts.servers[i])
		sslIDText := strings.TrimSpace(opts.sslIDs[i])

		if serverName == "" {
			fatalf("服务器名称不能为空")
			return 1
		}
		if sslIDText == "" {
			fatalf("SSL ID 不能为空")
			return 1
		}

		sslID, err := parseSSLID(sslIDText)
		if err != nil {
			fatalf("服务器 '%s' 的 SSL ID 无效: %s", serverName, sslIDText)
			return 1
		}

		server, err := resolveServer(config, serverName)
		if err != nil {
			fatalf("%v", err)
			return 1
		}

		logf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logf("服务器: %s", server.Name)
		logf("API: v%d", server.APIVersion)
		logf("SSL ID: %d", sslID)

		if err := processServer(server, sslID, opts.certFile, opts.keyFile, loc, opts.maxRetries, opts.retryInterval); err != nil {
			overallExitCode = 1
		}
	}

	if overallExitCode == 0 {
		logf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logf("全部证书推送完成")
		return 0
	}

	logf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logf("部分证书推送失败")
	return 1
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("ssl-uploader", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var sslIDs string
	var servers string
	configFile := defaultConfigFilePath()
	opts := options{
		certFile:       defaultCertFile,
		keyFile:        defaultKeyFile,
		configFile:     configFile,
		semiAutoWindow: defaultSemiAutoWindow,
		maxRetries:     defaultMaxRetries,
		retryInterval:  defaultRetryInterval,
	}

	fs.StringVar(&sslIDs, "s", "", "SSL ID 列表")
	fs.StringVar(&opts.certFile, "c", defaultCertFile, "证书文件路径")
	fs.StringVar(&opts.keyFile, "p", defaultKeyFile, "私钥文件路径")
	fs.StringVar(&servers, "S", "", "服务器列表")
	fs.StringVar(&opts.configFile, "C", configFile, "配置文件路径")
	fs.BoolVar(&opts.force, "f", false, "强制上传")
	fs.IntVar(&opts.semiAutoWindow, "m", defaultSemiAutoWindow, "半自动模式时间窗口")
	fs.IntVar(&opts.maxRetries, "r", defaultMaxRetries, "最大重试次数")
	fs.IntVar(&opts.retryInterval, "i", defaultRetryInterval, "重试间隔")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	opts.sslIDs = splitCSV(sslIDs)
	opts.servers = splitCSV(servers)
	if len(opts.sslIDs) == 0 {
		return options{}, fmt.Errorf("必须使用 -s 指定 SSL ID")
	}
	if len(opts.servers) == 0 {
		return options{}, fmt.Errorf("必须使用 -S 指定服务器")
	}
	if opts.semiAutoWindow < 0 {
		return options{}, fmt.Errorf("无效时间窗口: %d", opts.semiAutoWindow)
	}
	if opts.maxRetries <= 0 {
		return options{}, fmt.Errorf("无效重试次数: %d", opts.maxRetries)
	}
	if opts.retryInterval < 0 {
		return options{}, fmt.Errorf("无效重试间隔: %d", opts.retryInterval)
	}

	return opts, nil
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func defaultConfigFilePath() string {
	wd, err := os.Getwd()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(wd, "config.json")
}

func parseSSLID(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if parsed < 0 {
		return 0, fmt.Errorf("invalid ssl id")
	}
	return parsed, nil
}

func loadConfig(path string) (configFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return configFile{}, fmt.Errorf("配置文件读取失败: %w", err)
	}

	var cfg configFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return configFile{}, fmt.Errorf("配置文件不是有效的 JSON: %w", err)
	}
	return cfg, nil
}

func validateConfig(cfg configFile) error {
	if cfg.Version == 0 {
		return fmt.Errorf("配置文件缺少 version")
	}
	if cfg.Version != supportedConfigVersion {
		return fmt.Errorf("不支持的配置文件版本: %d（当前支持: %d）", cfg.Version, supportedConfigVersion)
	}
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("配置文件中没有配置任何服务器")
	}

	for name, server := range cfg.Servers {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("配置文件中的服务器名称不能为空")
		}
		if strings.TrimSpace(server.URL) == "" {
			return fmt.Errorf("服务器 '%s' 缺少有效的 url", name)
		}
		if strings.TrimSpace(server.Token) == "" {
			return fmt.Errorf("服务器 '%s' 缺少有效的 token", name)
		}
		apiVersion := defaultAPIVersion
		if server.APIVersion != nil {
			apiVersion = *server.APIVersion
		}
		if apiVersion != 1 && apiVersion != 2 {
			return fmt.Errorf("服务器 '%s' 的 api_version 无效: %d（只能是 1 或 2）", name, apiVersion)
		}
	}

	return nil
}

func resolveServer(cfg configFile, name string) (resolvedServer, error) {
	server, ok := cfg.Servers[name]
	if !ok {
		return resolvedServer{}, fmt.Errorf("配置文件中不存在服务器: %s", name)
	}
	apiVersion := defaultAPIVersion
	if server.APIVersion != nil {
		apiVersion = *server.APIVersion
	}
	return resolvedServer{
		Name:       name,
		URL:        strings.TrimSpace(server.URL),
		Token:      strings.TrimSpace(server.Token),
		APIVersion: apiVersion,
	}, nil
}

func checkCertificateFiles(certPath, keyPath string) error {
	if err := ensureReadableFile(certPath, "证书文件"); err != nil {
		return err
	}
	if err := ensureReadableFile(keyPath, "私钥文件"); err != nil {
		return err
	}
	return nil
}

func ensureReadableFile(path, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s不存在: %s", label, path)
		}
		return fmt.Errorf("%s检查失败: %w", label, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s不是文件: %s", label, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s不可读: %s", label, path)
	}
	_ = file.Close()
	return nil
}

func shouldUploadCertificate(certPath, keyPath string, force bool, windowSeconds int, loc *time.Location) (bool, error) {
	if force {
		logf("强制模式激活，跳过证书更新时间检测")
		return true, nil
	}

	currentTime := time.Now()
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return false, fmt.Errorf("获取证书文件信息失败: %w", err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return false, fmt.Errorf("获取私钥文件信息失败: %w", err)
	}

	latest := certInfo.ModTime()
	if keyInfo.ModTime().After(latest) {
		latest = keyInfo.ModTime()
	}

	diff := currentTime.Sub(latest)
	formatted := formatDisplayTime(latest, loc)
	if diff < 0 {
		warnf("证书文件修改时间位于未来（时钟可能不准确），将执行上传")
		return true, nil
	}
	if diff <= time.Duration(windowSeconds)*time.Second {
		logf("检测到证书文件最近发生变化 | 最后修改: %s | %d秒前", formatted, int(diff.Seconds()))
		return true, nil
	}

	logf("证书未发生近期更新 | 最后修改: %s | %d秒前", formatted, int(diff.Seconds()))
	return false, nil
}

func formatDisplayTime(t time.Time, loc *time.Location) string {
	return t.In(loc).Format("2006-01-02 15:04:05 MST (UTC-07:00)")
}

func displayLocation() *time.Location {
	zone := os.Getenv("TIME_ZONE")
	if zone == "" {
		zone = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		warnf("无法加载时区 %s，改用系统本地时区", zone)
		return time.Local
	}
	return loc
}

func processServer(server resolvedServer, sslID int64, certPath, keyPath string, loc *time.Location, maxRetries, retryInterval int) error {
	attempt := 1
	for attempt <= maxRetries {
		logf("[%s] 开始证书推送 (%d/%d)", server.Name, attempt, maxRetries)
		if err := attemptUpload(server, sslID, certPath, keyPath, loc); err == nil {
			return nil
		}
		if attempt >= maxRetries {
			logf("[%s] 已达到最大重试次数 (%d)", server.Name, maxRetries)
			return fmt.Errorf("[%s] upload failed", server.Name)
		}
		remaining := maxRetries - attempt
		logf("[%s] %d 秒后重试（剩余 %d 次）", server.Name, retryInterval, remaining)
		time.Sleep(time.Duration(retryInterval) * time.Second)
		attempt++
	}
	return fmt.Errorf("[%s] upload failed", server.Name)
}

func attemptUpload(server resolvedServer, sslID int64, certPath, keyPath string, loc *time.Location) error {
	now := time.Now()
	resp, err := performUpload(server, sslID, certPath, keyPath, loc, now, false)
	if err != nil {
		if isTLSVerificationError(err) {
			warnf("[%s] HTTPS/TLS 验证失败，将跳过证书验证重试", server.Name)
			resp, err = performUpload(server, sslID, certPath, keyPath, loc, now, true)
			if err != nil {
				logf("[%s] ✘ -k 重试仍然失败: %v", server.Name, err)
				return err
			}
		} else {
			logf("[%s] HTTP 请求失败: %v", server.Name, err)
			return err
		}
	}

	if resp.Code == 200 {
		if resp.Insecure {
			logf("[%s] ✔ 证书推送成功（WARNING: 本次跳过 HTTPS 证书验证） | API v%d | SSL ID: %d", server.Name, server.APIVersion, sslID)
		} else {
			logf("[%s] ✔ 证书推送成功 | API v%d | SSL ID: %d", server.Name, server.APIVersion, sslID)
		}
		return nil
	}

	message := resp.Message
	if strings.TrimSpace(message) == "" {
		message = "响应中没有 message 字段"
	}
	logf("[%s] ✘ 证书推送失败 | HTTP: %d | 业务码: %d", server.Name, resp.HTTPStatus, resp.Code)
	logf("[%s] 错误详情: %s", server.Name, truncateString(message, 500))
	return fmt.Errorf("[%s] upload failed", server.Name)
}

func performUpload(server resolvedServer, sslID int64, certPath, keyPath string, loc *time.Location, now time.Time, insecure bool) (uploadResponse, error) {
	apiPath, err := getAPIPath(server.APIVersion)
	if err != nil {
		return uploadResponse{}, err
	}

	payload, err := buildPayload(certPath, keyPath, sslID, fmt.Sprintf("同步更新 @%s", currentDisplayTime(now, loc)))
	if err != nil {
		return uploadResponse{}, fmt.Errorf("[%s] 请求数据构造失败: %w", server.Name, err)
	}

	requestURL := strings.TrimRight(server.URL, "/") + apiPath
	timestamp := now.Unix()
	panelToken := signToken(server.Token, timestamp)

	client := newHTTPClient(insecure)
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return uploadResponse{}, err
	}
	req.Header.Set("1Panel-Token", panelToken)
	req.Header.Set("1Panel-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("Content-Type", "application/json")

	logf("[%s] 请求 1Panel API v%d", server.Name, server.APIVersion)
	resp, err := client.Do(req)
	if err != nil {
		return uploadResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return uploadResponse{}, err
	}

	result := uploadResponse{HTTPStatus: resp.StatusCode, Insecure: insecure}
	var parsed struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &parsed)
	result.Code = parsed.Code
	result.Message = parsed.Message

	return result, nil
}

func buildPayload(certPath, keyPath string, sslID int64, description string) ([]byte, error) {
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	privateKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	payload := struct {
		Type        string `json:"type"`
		SSLID       int64  `json:"sslID"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"privateKey"`
		Description string `json:"description"`
	}{
		Type:        "paste",
		SSLID:       sslID,
		Certificate: string(certificate),
		PrivateKey:  string(privateKey),
		Description: description,
	}

	return json.Marshal(payload)
}

func signToken(apiKey string, timestamp int64) string {
	sum := md5.Sum([]byte(fmt.Sprintf("1panel%s%d", apiKey, timestamp)))
	return fmt.Sprintf("%x", sum)
}

func getAPIPath(apiVersion int) (string, error) {
	switch apiVersion {
	case 1:
		return "/api/v1/websites/ssl/upload", nil
	case 2:
		return "/api/v2/websites/ssl/upload", nil
	default:
		return "", fmt.Errorf("不支持的 1Panel API 版本: %d", apiVersion)
	}
}

func currentDisplayTime(now time.Time, loc *time.Location) string {
	return now.In(loc).Format("2006-01-02 15:04:05 MST (UTC-07:00)")
}

func newHTTPClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = (&net.Dialer{
		Timeout:   requestConnectTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = requestTLSHandshakeLimit
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   requestTotalTimeout,
	}
}

func isTLSVerificationError(err error) bool {
	var unknownAuthorityErr *x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalidErr *x509.CertificateInvalidError
	if errors.As(err, &unknownAuthorityErr) || errors.As(err, &hostnameErr) || errors.As(err, &certInvalidErr) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "x509:") || strings.Contains(message, "certificate")
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func logf(format string, args ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] WARNING: %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] ERROR: %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}
