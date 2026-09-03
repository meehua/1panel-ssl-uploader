// 1Panel SSL 上传工具：读取本地证书和私钥，按配置中的服务器信息上传到 1Panel。
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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// 默认证书和私钥路径。
	defaultCertFile = "./fullchain.pem"
	defaultKeyFile  = "./privkey.pem"

	// 自动模式下，默认认为最近 5 秒内有更新就触发上传。
	defaultAutoWindow = 5

	// 半自动模式下，默认允许 24 小时窗口内的修改被识别为需要上传。
	defaultSemiAutoWindow = 86400

	// 默认重试参数。
	defaultMaxRetries    = 8
	defaultRetryInterval = 15

	// 默认 1Panel API 版本。
	defaultAPIVersion = 2

	// HTTP 请求的超时控制。
	requestConnectTimeout    = 10 * time.Second
	requestTotalTimeout      = 60 * time.Second
	requestTLSHandshakeLimit = 10 * time.Second
)

// configFile 表示配置文件的结构体。
// 该工具不再要求配置文件携带 version 字段，避免无意义的版本锁定。
type configFile struct {
	Servers map[string]serverEntry `json:"servers"`
}

// serverEntry 表示单个服务器的配置字段。
type serverEntry struct {
	URL        string `json:"url,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	ServerIP   string `json:"server_ip,omitempty"`
	Token      string `json:"token"`
	APIVersion *int   `json:"api_version"`
}

// resolvedServer 是解析后的服务器配置，便于后续上传逻辑直接使用。
type resolvedServer struct {
	Name       string
	Protocol   string
	Host       string
	Port       int
	ServerIP   string
	Token      string
	APIVersion int
}

// options 保存命令行参数与运行时选项。
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

// uploadResponse 保存一次上传请求的响应信息。
type uploadResponse struct {
	HTTPStatus int
	Code       int
	Message    string
	Insecure   bool
}

// main 是程序入口，负责转交到 run() 并处理退出码。
func main() {
	os.Exit(run(os.Args[1:]))
}

// run 是主逻辑入口，完成参数解析、配置校验、证书判断和多目标上传。
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

	// 自动模式使用默认窗口；半自动模式使用自定义窗口。
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
		logf("全部服务器证书上传完成")
		return 0
	}

	logf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logf("部分服务器证书上传失败")
	return 1
}

// parseOptions 负责解析命令行参数，并给出必要的校验。
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

	fs.StringVar(&sslIDs, "ssl-id", "", "SSL ID 列表")
	fs.StringVar(&opts.certFile, "cert", defaultCertFile, "证书文件路径")
	fs.StringVar(&opts.keyFile, "key", defaultKeyFile, "私钥文件路径")
	fs.StringVar(&servers, "server", "", "服务器列表")
	fs.StringVar(&opts.configFile, "config", configFile, "配置文件路径")
	fs.BoolVar(&opts.force, "force", false, "强制上传")
	fs.IntVar(&opts.semiAutoWindow, "window", defaultSemiAutoWindow, "半自动模式时间窗口")
	fs.IntVar(&opts.maxRetries, "retries", defaultMaxRetries, "最大重试次数")
	fs.IntVar(&opts.retryInterval, "interval", defaultRetryInterval, "重试间隔")

	if err := fs.Parse(args); err != nil {
		return options{}, err
	}

	opts.sslIDs = splitCSV(sslIDs)
	opts.servers = splitCSV(servers)
	if len(opts.sslIDs) == 0 {
		return options{}, fmt.Errorf("必须使用 --ssl-id 指定 SSL ID")
	}
	if len(opts.servers) == 0 {
		return options{}, fmt.Errorf("必须使用 --server 指定服务器")
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

// splitCSV 将逗号分隔的字符串转为切片，并去掉空格。
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

// defaultConfigFilePath 返回可执行文件所在目录下的默认配置文件路径。
func defaultConfigFilePath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(exePath), "config.json")
}

// parseSSLID 把字符串型 SSL ID 转换为 int64，并校验非负性。
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

// loadConfig 从 JSON 文件中加载配置。
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

// validateConfig 检查配置文件的字段是否合法，并确保服务器配置完整。
func validateConfig(cfg configFile) error {
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("配置文件中没有配置任何服务器")
	}

	for name, server := range cfg.Servers {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("配置文件中的服务器名称不能为空")
		}
		if strings.TrimSpace(server.Token) == "" {
			return fmt.Errorf("服务器 '%s' 缺少有效的 token", name)
		}
		resolved, err := normalizeServerEntry(name, server)
		if err != nil {
			return err
		}
		if resolved.Protocol != "http" && resolved.Protocol != "https" {
			return fmt.Errorf("服务器 '%s' 的 protocol 无效: %s（只能是 http 或 https）", name, resolved.Protocol)
		}
		if resolved.Host == "" {
			return fmt.Errorf("服务器 '%s' 缺少有效的 host", name)
		}
		if resolved.Port < 1 || resolved.Port > 65535 {
			return fmt.Errorf("服务器 '%s' 的 port 无效: %d", name, resolved.Port)
		}
		if resolved.APIVersion != 1 && resolved.APIVersion != 2 {
			return fmt.Errorf("服务器 '%s' 的 api_version 无效: %d（只能是 1 或 2）", name, resolved.APIVersion)
		}
	}

	return nil
}

// resolveServer 解析并规范化服务器配置，返回可直接上传的对象。
func resolveServer(cfg configFile, name string) (resolvedServer, error) {
	server, ok := cfg.Servers[name]
	if !ok {
		return resolvedServer{}, fmt.Errorf("配置文件中不存在服务器: %s", name)
	}
	return normalizeServerEntry(name, server)
}

// normalizeServerEntry 将配置中的服务器定义解析成标准化结构。
func normalizeServerEntry(name string, server serverEntry) (resolvedServer, error) {
	apiVersion := defaultAPIVersion
	if server.APIVersion != nil {
		apiVersion = *server.APIVersion
	}

	protocol := strings.ToLower(strings.TrimSpace(server.Protocol))
	host := strings.TrimSpace(server.Host)
	port := server.Port
	serverIP := strings.TrimSpace(server.ServerIP)

	if protocol == "" && host == "" && port == 0 {
		parsedProtocol, parsedHost, parsedPort, err := parseLegacyServerURL(server.URL)
		if err != nil {
			return resolvedServer{}, fmt.Errorf("服务器 '%s' 的 url 无效: %w", name, err)
		}
		protocol = parsedProtocol
		host = parsedHost
		port = parsedPort
	}

	if protocol == "" {
		return resolvedServer{}, fmt.Errorf("服务器 '%s' 缺少有效的 protocol", name)
	}
	if host == "" {
		return resolvedServer{}, fmt.Errorf("服务器 '%s' 缺少有效的 host", name)
	}
	if port == 0 {
		port = defaultPortForProtocol(protocol)
	}
	if port < 1 || port > 65535 {
		return resolvedServer{}, fmt.Errorf("服务器 '%s' 的 port 无效: %d", name, port)
	}
	if protocol != "http" && protocol != "https" {
		return resolvedServer{}, fmt.Errorf("服务器 '%s' 的 protocol 无效: %s（只能是 http 或 https）", name, protocol)
	}

	return resolvedServer{
		Name:       name,
		Protocol:   protocol,
		Host:       host,
		Port:       port,
		ServerIP:   serverIP,
		Token:      strings.TrimSpace(server.Token),
		APIVersion: apiVersion,
	}, nil
}

// parseLegacyServerURL 将旧配置中的 url 拆分为协议、主机和端口。
func parseLegacyServerURL(rawURL string) (string, string, int, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", 0, fmt.Errorf("url 不能为空")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", 0, err
	}
	if parsed.Scheme == "" {
		return "", "", 0, fmt.Errorf("缺少协议")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", "", 0, fmt.Errorf("缺少主机")
	}
	portText := strings.TrimSpace(parsed.Port())
	port := defaultPortForProtocol(strings.ToLower(parsed.Scheme))
	if portText != "" {
		parsedPort, err := strconv.Atoi(portText)
		if err != nil {
			return "", "", 0, fmt.Errorf("端口无效: %s", portText)
		}
		port = parsedPort
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", "", 0, fmt.Errorf("url 中不应包含路径: %s", parsed.Path)
	}
	return strings.ToLower(parsed.Scheme), host, port, nil
}

// defaultPortForProtocol 返回协议对应的默认端口。
func defaultPortForProtocol(protocol string) int {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// checkCertificateFiles 检查证书和私钥是否存在且可读。
func checkCertificateFiles(certPath, keyPath string) error {
	if err := ensureReadableFile(certPath, "证书文件"); err != nil {
		return err
	}
	if err := ensureReadableFile(keyPath, "私钥文件"); err != nil {
		return err
	}
	return nil
}

// ensureReadableFile 确保给定路径是存在且可读取的普通文件。
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

// shouldUploadCertificate 根据证书/私钥最近修改时间判断是否需要上传。
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

// formatDisplayTime 将时间转换为可读的本地格式。
func formatDisplayTime(t time.Time, loc *time.Location) string {
	return t.In(loc).Format("2006-01-02 15:04:05 MST (UTC-07:00)")
}

// displayLocation 读取环境变量 TIME_ZONE，若为空则回退到亚洲/上海。
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

// processServer 按服务器逐个执行上传，并在失败时按策略重试。
func processServer(server resolvedServer, sslID int64, certPath, keyPath string, loc *time.Location, maxRetries, retryInterval int) error {
	attempt := 1
	for attempt <= maxRetries {
		logf("[%s] 开始证书上传 (%d/%d)", server.Name, attempt, maxRetries)
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

// attemptUpload 触发一次上传，并在 TLS 验证错误时尝试 insecure 模式重试。
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
			logf("[%s] ✔ 证书上传成功（WARNING: 本次跳过 HTTPS 证书验证） | API v%d | SSL ID: %d", server.Name, server.APIVersion, sslID)
		} else {
			logf("[%s] ✔ 证书上传成功 | API v%d | SSL ID: %d", server.Name, server.APIVersion, sslID)
		}
		return nil
	}

	message := resp.Message
	if strings.TrimSpace(message) == "" {
		message = "响应中没有 message 字段"
	}
	logf("[%s] ✘ 证书上传失败 | HTTP: %d | 业务码: %d", server.Name, resp.HTTPStatus, resp.Code)
	logf("[%s] 错误详情: %s", server.Name, truncateString(message, 500))
	return fmt.Errorf("[%s] upload failed", server.Name)
}

// performUpload 执行实际的 HTTP POST 上传，构造签名头与 JSON 载荷。
func performUpload(server resolvedServer, sslID int64, certPath, keyPath string, loc *time.Location, now time.Time, insecure bool) (uploadResponse, error) {
	apiPath, err := getAPIPath(server.APIVersion)
	if err != nil {
		return uploadResponse{}, err
	}

	payload, err := buildPayload(certPath, keyPath, sslID, fmt.Sprintf("同步更新 @%s", currentDisplayTime(now, loc)))
	if err != nil {
		return uploadResponse{}, fmt.Errorf("[%s] 请求数据构造失败: %w", server.Name, err)
	}

	requestURL := server.requestURL(apiPath)
	timestamp := now.Unix()
	panelToken := signToken(server.Token, timestamp)

	client := newHTTPClient(insecure, server.hostNameForTLS())
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return uploadResponse{}, err
	}
	req.Host = server.hostHeader()
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

// requestURL 生成上传请求的完整目标地址。
func (s resolvedServer) requestURL(apiPath string) string {
	host := s.Host
	if strings.TrimSpace(s.ServerIP) != "" {
		host = s.ServerIP
	}
	baseURL := fmt.Sprintf("%s://%s", s.Protocol, net.JoinHostPort(host, strconv.Itoa(s.Port)))
	return strings.TrimRight(baseURL, "/") + apiPath
}

// hostHeader 返回需要写入请求的 Host 头。
func (s resolvedServer) hostHeader() string {
	if s.Port == defaultPortForProtocol(s.Protocol) || s.Port == 0 {
		return s.Host
	}
	return net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
}

// hostNameForTLS 返回 TLS SNI / 证书校验使用的主机名。
func (s resolvedServer) hostNameForTLS() string {
	return s.Host
}

// buildPayload 拼装上传到 1Panel 的 JSON 请求体。
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

// signToken 根据 API Token 和时间戳生成 1Panel 签名。
func signToken(apiKey string, timestamp int64) string {
	sum := md5.Sum(fmt.Appendf(nil, "1panel%s%d", apiKey, timestamp))
	return fmt.Sprintf("%x", sum)
}

// getAPIPath 根据 1Panel API 版本返回对应的上传接口路径。
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

// currentDisplayTime 根据本地时区返回展示用时间字符串。
func currentDisplayTime(now time.Time, loc *time.Location) string {
	return now.In(loc).Format("2006-01-02 15:04:05 MST (UTC-07:00)")
}

// newHTTPClient 构造带超时和 TLS 配置的 HTTP 客户端。
func newHTTPClient(insecure bool, serverName string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = (&net.Dialer{
		Timeout:   requestConnectTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = requestTLSHandshakeLimit
	if insecure || strings.TrimSpace(serverName) != "" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure, ServerName: strings.TrimSpace(serverName)}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   requestTotalTimeout,
	}
}

// isTLSVerificationError 判断错误是否为 TLS/证书校验失败。
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

// truncateString 裁剪字符串到固定长度，避免日志过长。
func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// logf 输出普通日志。
func logf(format string, args ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// warnf 输出警告日志。
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] WARNING: %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// fatalf 输出错误日志并终止运行。
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] ERROR: %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}
