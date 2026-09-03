#!/usr/bin/env bash

# 1Panel SSL Uploader
#
# 用途：
#   检测 SSL 证书/私钥是否更新，并将其上传到一个或多个 1Panel 实例。
#
# 特性：
#   - 支持 1Panel API v1 / v2
#   - 每个服务器可以单独指定 API 版本
#   - 使用 JSON 配置文件
#   - 使用 jq 构造 JSON 请求，避免手工拼接 JSON
#   - curl 不再依赖 %{json}，兼容旧版 curl
#   - HTTPS 证书校验失败时自动以 -k 重试，并输出 WARNING
#   - 支持失败重试
#   - 支持强制上传
#   - 支持证书更新时间窗口检测
#
# 配置文件：
#
#   {
#     "version": 1,
#     "servers": {
#       "home": {
#         "url": "https://192.168.1.10:9999",
#         "token": "your-api-token",
#         "api_version": 2
#       },
#       "old-panel": {
#         "url": "https://example.com:9999",
#         "token": "your-api-token",
#         "api_version": 1
#       }
#     }
#   }
#
# 使用：
#
#   ./script.sh -s 123 -S home
#   ./script.sh -s 123,456 -S home,old-panel
#   ./script.sh -s 123 -S home -f
#
# 参数：
#
#   -s SSL ID 列表，多个 ID 用逗号分隔
#   -S 服务器名称列表，多个名称用逗号分隔
#   -c 证书文件路径
#   -p 私钥文件路径
#   -C JSON 配置文件路径
#   -f 强制上传，跳过证书更新时间检测
#   -m 半自动模式时间窗口（秒）
#   -r 最大重试次数
#   -i 重试间隔（秒）
#
# 说明：
#
#   -s 和 -S 按位置一一对应：
#
#       -s 123,456 -S home,old-panel
#
#   表示：
#
#       SSL ID 123 -> home
#       SSL ID 456 -> old-panel
#
# 安全：
#
#   默认先进行正常 HTTPS 证书验证。
#   如果 curl 因 TLS/证书验证失败，则输出 WARNING，
#   随后使用 -k 跳过证书验证重试。
#
#   如果你的 1Panel 使用可信 CA 签发的证书，则不会使用 -k。
#
# 配置文件建议：
#
#   chmod 600 config.json
#
# 依赖：
#
#   bash
#   curl
#   jq
#   coreutils（md5sum、stat、date 等）
#

set -Eeuo pipefail


# ============================================================================
# 全局配置
# ============================================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

DEFAULT_CONFIG_FILE="${SCRIPT_DIR}/config.json"

DEFAULT_CERT_FILE="./fullchain.pem"
DEFAULT_KEY_FILE="./privkey.pem"

# 默认自动检测窗口：
# 证书/私钥在最近多少秒内发生变化才执行上传。
DEFAULT_AUTO_WINDOW=5

# 使用自定义证书路径时的默认检测窗口。
DEFAULT_SEMI_AUTO_WINDOW=86400

# 默认重试次数。
DEFAULT_MAX_RETRIES=8

# 默认重试间隔。
DEFAULT_RETRY_INTERVAL=15

# 配置文件格式版本。
SUPPORTED_CONFIG_VERSION=1

# 默认 1Panel API 版本。
#
# 如果服务器配置没有填写 api_version，则使用 v2。
DEFAULT_API_VERSION=2


# ============================================================================
# 日志
# ============================================================================

log() {
    printf '[%s] %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" \
        "$1"
}


warn() {
    log "WARNING: $1" >&2
}


die() {
    log "ERROR: $1" >&2
    exit 1
}


# ============================================================================
# 错误处理
# ============================================================================

on_error() {
    local exit_code=$?
    local line_no=${1:-unknown}

    log "ERROR: 脚本执行失败（退出码: ${exit_code}，行号: ${line_no}）" >&2

    exit "$exit_code"
}

trap 'on_error "$LINENO"' ERR


# ============================================================================
# 工具检查
# ============================================================================

require_command() {
    local command_name="$1"
    local install_hint="${2:-}"

    if command -v "$command_name" >/dev/null 2>&1; then
        return 0
    fi

    if [[ -n "$install_hint" ]]; then
        die "缺少依赖命令: ${command_name}（${install_hint}）"
    fi

    die "缺少依赖命令: ${command_name}"
}


check_runtime_dependencies() {
    require_command "curl" "请安装 curl"
    require_command "jq" "请安装 jq"
    require_command "md5sum" "请安装 coreutils"
    require_command "stat"
    require_command "date"
    require_command "sed"
    require_command "cut"

    # 不通过版本号判断 jq。
    #
    # 直接测试脚本实际需要的功能。
    #
    # 这样比自己实现版本比较器更加可靠。
    if ! jq -n 'null // empty' >/dev/null 2>&1; then
        die "当前 jq 不支持脚本所需功能，请安装 jq 1.5 或更高版本"
    fi

    local curl_version
    local jq_version

    curl_version="$(
        curl --version |
            sed -n '1{s/^curl //;s/ .*//;p}'
    )"

    jq_version="$(jq --version)"

    log "运行环境检查通过 | curl ${curl_version} | ${jq_version}"
}


# ============================================================================
# 配置文件
# ============================================================================

validate_config() {
    local config_file="$1"

    # 检查 JSON 是否有效。
    if ! jq -e empty "$config_file" >/dev/null 2>&1; then
        die "配置文件不是有效的 JSON: ${config_file}"
    fi


    # ------------------------------------------------------------------------
    # 检查顶层 version
    # ------------------------------------------------------------------------

    local config_version

    config_version="$(
        jq -er '.version // empty' "$config_file"
    )" || die "配置文件缺少 version"

    [[ "$config_version" =~ ^[0-9]+$ ]] ||
        die "配置文件 version 必须是数字"

    if [[ "$config_version" -ne "$SUPPORTED_CONFIG_VERSION" ]]; then
        die "不支持的配置文件版本: ${config_version}（当前支持: ${SUPPORTED_CONFIG_VERSION}）"
    fi


    # ------------------------------------------------------------------------
    # 检查 servers
    # ------------------------------------------------------------------------

    jq -e '.servers | type == "object"' "$config_file" >/dev/null 2>&1 ||
        die "配置文件中的 servers 必须是 JSON object"


    # 至少需要一个服务器。
    local server_count

    server_count="$(
        jq -er '.servers | length' "$config_file"
    )"

    if [[ "$server_count" -eq 0 ]]; then
        die "配置文件中没有配置任何服务器"
    fi


    # ------------------------------------------------------------------------
    # 检查每个服务器
    # ------------------------------------------------------------------------

    local server
    local url
    local token
    local api_version

    while IFS= read -r server; do

        [[ -n "$server" ]] || continue


        # URL
        if ! jq -e \
            --arg server "$server" \
            '.servers[$server].url | type == "string" and length > 0' \
            "$config_file" >/dev/null 2>&1; then

            die "服务器 '${server}' 缺少有效的 url"
        fi


        # Token
        if ! jq -e \
            --arg server "$server" \
            '.servers[$server].token | type == "string" and length > 0' \
            "$config_file" >/dev/null 2>&1; then

            die "服务器 '${server}' 缺少有效的 token"
        fi


        # API Version
        api_version="$(
            jq -er \
                --arg server "$server" \
                '.servers[$server].api_version // 2' \
                "$config_file"
        )" || die "服务器 '${server}' 的 api_version 无法解析"


        [[ "$api_version" =~ ^[12]$ ]] ||
            die "服务器 '${server}' 的 api_version 无效: ${api_version}（只能是 1 或 2）"


        # 确保服务器本身是 object。
        if ! jq -e \
            --arg server "$server" \
            '.servers[$server] | type == "object"' \
            "$config_file" >/dev/null 2>&1; then

            die "服务器 '${server}' 配置必须是 JSON object"
        fi

    done < <(
        jq -r '.servers | keys[]' "$config_file"
    )


    log "配置文件检查通过 | ${server_count} 个服务器"
}


get_server_config() {
    local config_file="$1"
    local server="$2"

    # 使用 jq -r 获取字符串。
    # 如果字段不存在则返回失败。
    SERVER_API_URL="$(
        jq -er \
            --arg server "$server" \
            '.servers[$server].url' \
            "$config_file"
    )"

    SERVER_API_KEY="$(
        jq -er \
            --arg server "$server" \
            '.servers[$server].token' \
            "$config_file"
    )"

    SERVER_API_VERSION="$(
        jq -er \
            --arg server "$server" \
            '.servers[$server].api_version // 2' \
            "$config_file"
    )"
}


# ============================================================================
# API 路径
# ============================================================================

get_api_path() {
    local api_version="$1"

    case "$api_version" in

        1)
            printf '%s\n' "/api/v1/websites/ssl/upload"
            ;;

        2)
            printf '%s\n' "/api/v2/websites/ssl/upload"
            ;;

        *)
            die "不支持的 1Panel API 版本: ${api_version}"
            ;;

    esac
}


# ============================================================================
# 证书更新时间检测
# ============================================================================

check_certificate_files() {
    [[ -f "$CERT_FILE" ]] ||
        die "证书文件不存在: ${CERT_FILE}"

    [[ -r "$CERT_FILE" ]] ||
        die "证书文件不可读: ${CERT_FILE}"


    [[ -f "$KEY_FILE" ]] ||
        die "私钥文件不存在: ${KEY_FILE}"

    [[ -r "$KEY_FILE" ]] ||
        die "私钥文件不可读: ${KEY_FILE}"
}


should_upload_certificate() {

    # 强制模式。
    if (( force_mode == 1 )); then
        log "强制模式激活，跳过证书更新时间检测"
        return 0
    fi


    local current_ts
    local cert_ts
    local key_ts
    local latest_ts
    local time_diff
    local formatted_time


    current_ts="$(date +%s)"

    cert_ts="$(stat -c %Y "$CERT_FILE")"
    key_ts="$(stat -c %Y "$KEY_FILE")"


    # 取证书和私钥中较新的修改时间。
    if (( cert_ts > key_ts )); then
        latest_ts="$cert_ts"
    else
        latest_ts="$key_ts"
    fi


    time_diff=$((current_ts - latest_ts))


    # 如果文件时间来自未来，不应该导致上传被跳过。
    if (( time_diff < 0 )); then
        warn "证书文件修改时间位于未来（时钟可能不准确），将执行上传"
        return 0
    fi


    if (( time_diff <= current_window )); then

        formatted_time="$(
            TZ="${TIME_ZONE:-Asia/Shanghai}" \
                date -d "@${latest_ts}" \
                    '+%Y-%m-%d %H:%M:%S %Z (UTC%:z)'
        )"

        log "检测到证书文件最近发生变化 | 最后修改: ${formatted_time} | ${time_diff}秒前"

        return 0
    fi


    formatted_time="$(
        TZ="${TIME_ZONE:-Asia/Shanghai}" \
            date -d "@${latest_ts}" \
                '+%Y-%m-%d %H:%M:%S %Z (UTC%:z)'
    )"

    log "证书未发生近期更新 | 最后修改: ${formatted_time} | ${time_diff}秒前"

    return 1
}


# ============================================================================
# API 请求
# ============================================================================

execute_api_request() {
    local api_url="$1"
    local api_key="$2"
    local server_name="$3"
    local ssl_id="$4"
    local api_version="$5"


    local current_ts
    local panel_token
    local current_time
    local api_path
    local request_url
    local payload

    local response
    local curl_exit

    local resp_body
    local http_code
    local resp_code
    local resp_msg

    local use_insecure=0


    current_ts="$(date +%s)"


    # ------------------------------------------------------------------------
    # 生成 1Panel Token
    # ------------------------------------------------------------------------

    panel_token="$(
        printf '1panel%s%s' "$api_key" "$current_ts" |
            md5sum |
            cut -d' ' -f1
    )"


    current_time="$(
        TZ="${TIME_ZONE:-Asia/Shanghai}" \
            date '+%Y-%m-%d %H:%M:%S %Z (UTC%:z)'
    )"


    # ------------------------------------------------------------------------
    # API 路径
    # ------------------------------------------------------------------------

    api_path="$(get_api_path "$api_version")"

    request_url="${api_url%/}${api_path}"


    # ------------------------------------------------------------------------
    # 构造 JSON
    # ------------------------------------------------------------------------
    #
    # 使用 jq --rawfile 直接读取证书和私钥。
    #
    # 不再：
    #
    #   jq -Rs
    #       ↓
    #   sed
    #       ↓
    #   手工拼 JSON
    #
    # jq 会负责全部 JSON escaping。
    #

    payload="$(
        jq -n \
            --rawfile certificate "$CERT_FILE" \
            --rawfile privateKey "$KEY_FILE" \
            --argjson sslID "$ssl_id" \
            --arg description "同步更新 @${current_time}" \
            '{
                type: "paste",
                sslID: $sslID,
                certificate: $certificate,
                privateKey: $privateKey,
                description: $description
            }'
    )" || {
        die "[${server_name}] 请求数据构造失败"
    }


    # ------------------------------------------------------------------------
    # 第一次请求：正常验证 TLS
    # ------------------------------------------------------------------------

    log "[${server_name}] 请求 1Panel API v${api_version}"

    set +e

    response="$(
        curl \
            -sS \
            --connect-timeout 10 \
            --max-time 60 \
            -w $'\n%{http_code}' \
            -X POST \
            "$request_url" \
            -H "1Panel-Token: ${panel_token}" \
            -H "1Panel-Timestamp: ${current_ts}" \
            -H "Content-Type: application/json" \
            --data "$payload"
    )"

    curl_exit=$?

    set -e


    # ------------------------------------------------------------------------
    # 如果 TLS 证书校验失败，使用 -k 重试
    # ------------------------------------------------------------------------
    #
    # curl 60：
    #   SSL certificate problem
    #
    # curl 51：
    #   SSL peer certificate or SSH remote key was not OK
    #
    # curl 53：
    #   SSL crypto engine failure
    #
    # curl 35：
    #   SSL connect error
    #
    # curl 77：
    #   Problem with the SSL CA cert
    #
    # 这些错误不一定全部意味着“证书有问题”，
    # 但都属于 TLS 层面的错误。
    #
    # 因此这里输出 WARNING 后尝试 -k。
    #

    if (( curl_exit != 0 )); then

        case "$curl_exit" in

            35|51|53|60|77)

                warn "[${server_name}] HTTPS/TLS 验证失败（curl退出码: ${curl_exit}），将跳过证书验证重试"

                use_insecure=1
                ;;

            *)

                log "[${server_name}] curl 请求失败（退出码: ${curl_exit}）"

                return 1
                ;;

        esac

    fi


    # ------------------------------------------------------------------------
    # -k 重试
    # ------------------------------------------------------------------------

    if (( use_insecure == 1 )); then

        set +e

        response="$(
            curl \
                -sSk \
                --connect-timeout 10 \
                --max-time 60 \
                -w $'\n%{http_code}' \
                -X POST \
                "$request_url" \
                -H "1Panel-Token: ${panel_token}" \
                -H "1Panel-Timestamp: ${current_ts}" \
                -H "Content-Type: application/json" \
                --data "$payload"
        )"

        curl_exit=$?

        set -e

        if (( curl_exit != 0 )); then
            log "[${server_name}] ✘ -k 重试仍然失败（curl退出码: ${curl_exit}）"
            return 1
        fi

    fi


    # ------------------------------------------------------------------------
    # 分离 HTTP 状态码
    # ------------------------------------------------------------------------

    resp_body="$response"
    http_code="000"


    if [[ "$response" == *$'\n'* ]]; then

        resp_body="${response%$'\n'*}"
        http_code="${response##*$'\n'}"

    fi


    [[ "$http_code" =~ ^[0-9]{3}$ ]] ||
        http_code="000"


    # ------------------------------------------------------------------------
    # HTTP 请求失败
    # ------------------------------------------------------------------------

    if [[ "$http_code" == "000" ]]; then

        log "[${server_name}] ✘ 未获得有效 HTTP 响应"

        return 1

    fi


    # ------------------------------------------------------------------------
    # 解析 1Panel JSON
    # ------------------------------------------------------------------------

    resp_code="$(
        jq -r '.code // empty' <<< "$resp_body" 2>/dev/null || true
    )"

    resp_msg="$(
        jq -r '.message // empty' <<< "$resp_body" 2>/dev/null || true
    )"


    # ------------------------------------------------------------------------
    # API 成功
    # ------------------------------------------------------------------------

    if [[ "$resp_code" == "200" ]]; then

        if (( use_insecure == 1 )); then
            log "[${server_name}] ✔ 证书推送成功（WARNING: 本次跳过 HTTPS 证书验证） | API v${api_version} | SSL ID: ${ssl_id}"
        else
            log "[${server_name}] ✔ 证书推送成功 | API v${api_version} | SSL ID: ${ssl_id}"
        fi

        return 0

    fi


    # ------------------------------------------------------------------------
    # API 业务失败
    # ------------------------------------------------------------------------

    [[ -n "$resp_msg" ]] ||
        resp_msg="响应中没有 message 字段"


    log "[${server_name}] ✘ 证书推送失败 | HTTP: ${http_code} | 业务码: ${resp_code:-未知}"
    log "[${server_name}] 错误详情: ${resp_msg:0:500}"

    return 1
}


# ============================================================================
# 单服务器处理
# ============================================================================

process_server() {
    local api_url="$1"
    local api_key="$2"
    local server_name="$3"
    local ssl_id="$4"
    local api_version="$5"


    local attempt=1
    local remaining_attempts


    while (( attempt <= max_retries )); do

        log "[${server_name}] 开始证书推送 (${attempt}/${max_retries})"


        if execute_api_request \
            "$api_url" \
            "$api_key" \
            "$server_name" \
            "$ssl_id" \
            "$api_version"; then

            return 0

        fi


        if (( attempt >= max_retries )); then

            log "[${server_name}] 已达到最大重试次数 (${max_retries})"

            return 1

        fi


        remaining_attempts=$((max_retries - attempt))


        log "[${server_name}] ${retry_interval} 秒后重试（剩余 ${remaining_attempts} 次）"

        sleep "$retry_interval"

        # 不使用 ((attempt++))。
        #
        # 在 set -e 下：
        #
        #   ((attempt++))
        #
        # 第一次执行时可能返回状态码 1，
        # 从而导致脚本提前退出。
        attempt=$((attempt + 1))

    done


    return 1
}


# ============================================================================
# 参数
# ============================================================================

force_mode=0

current_window="$DEFAULT_AUTO_WINDOW"

max_retries="$DEFAULT_MAX_RETRIES"
retry_interval="$DEFAULT_RETRY_INTERVAL"

CERT_FILE="$DEFAULT_CERT_FILE"
KEY_FILE="$DEFAULT_KEY_FILE"
CONFIG_FILE="$DEFAULT_CONFIG_FILE"

semi_auto_window="$DEFAULT_SEMI_AUTO_WINDOW"

SSLID_LIST=()
SERVER_LIST=()


# ============================================================================
# 参数解析
# ============================================================================

while getopts ":s:c:p:S:C:fm:r:i:" opt; do

    case "$opt" in

        s)
            IFS=',' read -r -a SSLID_LIST <<< "$OPTARG"
            ;;

        c)
            CERT_FILE="$OPTARG"
            ;;

        p)
            KEY_FILE="$OPTARG"
            ;;

        S)
            IFS=',' read -r -a SERVER_LIST <<< "$OPTARG"
            ;;

        C)
            CONFIG_FILE="$OPTARG"
            ;;

        f)
            force_mode=1
            ;;

        m)
            semi_auto_window="$OPTARG"

            [[ "$semi_auto_window" =~ ^[0-9]+$ ]] ||
                die "无效时间窗口: ${semi_auto_window}"

            ;;

        r)
            max_retries="$OPTARG"

            [[ "$max_retries" =~ ^[1-9][0-9]*$ ]] ||
                die "无效重试次数: ${max_retries}"

            ;;

        i)
            retry_interval="$OPTARG"

            [[ "$retry_interval" =~ ^[0-9]+$ ]] ||
                die "无效重试间隔: ${retry_interval}"

            ;;

        :)
            die "选项 -${OPTARG} 缺少参数"
            ;;

        \?)
            die "未知选项: -${OPTARG}"
            ;;

    esac

done

shift $((OPTIND - 1))


# ============================================================================
# 参数验证
# ============================================================================

[[ ${#SSLID_LIST[@]} -gt 0 ]] ||
    die "必须使用 -s 指定 SSL ID"

[[ ${#SERVER_LIST[@]} -gt 0 ]] ||
    die "必须使用 -S 指定服务器"


if [[ ${#SSLID_LIST[@]} -ne ${#SERVER_LIST[@]} ]]; then

    die \
        "SSL ID 数量（${#SSLID_LIST[@]}）与服务器数量（${#SERVER_LIST[@]}）不匹配"

fi


# ============================================================================
# 运行环境
# ============================================================================

check_runtime_dependencies


# ============================================================================
# 配置文件
# ============================================================================

[[ -f "$CONFIG_FILE" ]] ||
    die "配置文件不存在: ${CONFIG_FILE}"

[[ -r "$CONFIG_FILE" ]] ||
    die "配置文件不可读: ${CONFIG_FILE}"

validate_config "$CONFIG_FILE"


# ============================================================================
# 证书文件
# ============================================================================

check_certificate_files


# ============================================================================
# 检测模式
# ============================================================================

if [[ "$CERT_FILE" != "$DEFAULT_CERT_FILE" ||
      "$KEY_FILE" != "$DEFAULT_KEY_FILE" ]]; then

    current_window="$semi_auto_window"

    log "半自动模式激活 | 时间窗口: ${current_window} 秒"

else

    current_window="$DEFAULT_AUTO_WINDOW"

fi


# ============================================================================
# 证书更新时间
# ============================================================================

if ! should_upload_certificate; then

    exit 0

fi


# ============================================================================
# 执行上传
# ============================================================================

overall_exit_code=0


for i in "${!SERVER_LIST[@]}"; do

    server="${SERVER_LIST[$i]}"
    ssl_id="${SSLID_LIST[$i]}"


    [[ -n "$server" ]] ||
        die "服务器名称不能为空"

    [[ -n "$ssl_id" ]] ||
        die "SSL ID 不能为空"


    # SSL ID 必须是数字。
    [[ "$ssl_id" =~ ^[0-9]+$ ]] ||
        die "服务器 '${server}' 的 SSL ID 无效: ${ssl_id}"


    # ------------------------------------------------------------------------
    # 读取服务器配置
    # ------------------------------------------------------------------------

    if ! jq -e \
        --arg server "$server" \
        '.servers | has($server)' \
        "$CONFIG_FILE" >/dev/null 2>&1; then

        die "配置文件中不存在服务器: ${server}"

    fi


    get_server_config "$CONFIG_FILE" "$server"


    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    log "服务器: ${server}"
    log "API: v${SERVER_API_VERSION}"
    log "SSL ID: ${ssl_id}"


    # ------------------------------------------------------------------------
    # 上传
    # ------------------------------------------------------------------------

    if ! process_server \
        "$SERVER_API_URL" \
        "$SERVER_API_KEY" \
        "$server" \
        "$ssl_id" \
        "$SERVER_API_VERSION"; then

        overall_exit_code=1

    fi

done


# ============================================================================
# 完成
# ============================================================================

if (( overall_exit_code == 0 )); then

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "全部证书推送完成"

else

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "部分证书推送失败"

fi


exit "$overall_exit_code"