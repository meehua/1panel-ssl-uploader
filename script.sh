#!/usr/bin/env bash

# 仓库 https://github.com/meehua/1panel-ssl-uploader
# 使用方法 https://www.l0u0l.com/posts/1panel-ssl-uploader/

### 全局配置区 ========================================================
# 注意：以下配置项在使用前可能需要修改
TIME_ZONE="Asia/Shanghai"                 # 时区设置（用于日志时间显示）

# 默认配置文件路径（基于脚本所在目录）
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")  # 自动获取脚本所在目录
DEFAULT_CONFIG_FILE="${SCRIPT_DIR}/config"   # 配置文件与脚本同目录

# 默认证书路径（可通过命令行参数覆盖）
DEFAULT_CERT_FILE="./fullchain.pem"       # 默认证书文件路径（修改会导致自动模式失效）
DEFAULT_KEY_FILE="./privkey.pem"          # 默认私钥文件路径（修改会导致自动模式失效）

# 时间窗口配置（单位：秒）
DEFAULT_AUTO_WINDOW=5                     # 自动模式检测阈值（默认证书路径）
DEFAULT_SEMI_AUTO_WINDOW=86400            # 半自动模式检测阈值（自定义证书路径）

# 重试配置
DEFAULT_MAX_RETRIES=8                     # 默认最大重试次数
DEFAULT_RETRY_INTERVAL=15                 # 默认重试间隔时间（秒）

### 函数定义 ==========================================================
# 输出带时间戳的日志信息
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# 终止脚本并显示错误信息
die() {
    log "ERROR: $1" >&2
    exit 1
}

# 解析配置文件
parse_config_file() {
    local config_file=$1
    declare -gA SERVER_CONFIG
    
    local current_section=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        if [[ $line =~ ^\[([a-zA-Z0-9_\.-]+)\]$ ]]; then
            current_section="${BASH_REMATCH[1]}"
        elif [[ $line =~ ^([a-zA-Z0-9_]+)[[:space:]]*=[[:space:]]*\"?(.*?)\"?$ ]]; then
            local key="${BASH_REMATCH[1],,}"
            local value="${BASH_REMATCH[2]}"
            SERVER_CONFIG["${current_section}.${key}"]="${value//\"/}"
        fi
    done < "$config_file"
}

# 执行API请求并处理响应
execute_api_request() {
    local api_url=$1
    local api_key=$2
    local server_name=$3
    local ssl_id=$4
    
    local current_ts=$(date +%s)
    local panel_token=$(echo -n "1panel${api_key}${current_ts}" | md5sum | cut -d' ' -f1)
    local current_time=$(TZ=$TIME_ZONE date '+%Y-%m-%d %H:%M:%S %Z (UTC%:z)')

    # 构造并发送API请求
    local response=$(curl -sSk -w "\n%{json}" -X POST "$api_url/api/v2/websites/ssl/upload" \
        -H "1Panel-Token: $panel_token" \
        -H "1Panel-Timestamp: $current_ts" \
        -H "Content-Type: application/json" \
        -d "$(cat <<EOF
{
    "type": "paste",
    "sslID": $ssl_id,
    "certificate": "$cert_content",
    "privateKey": "$key_content",
    "description": "同步更新 @$current_time"
}
EOF
    )")

    # 解析响应结果
    local resp_body=$(sed '$d' <<< "$response")
    local curl_info=$(tail -n1 <<< "$response")
    local http_code=$(jq -r '.http_code' <<< "$curl_info")
    local resp_code=$(jq -r '.code' <<< "$resp_body" 2>/dev/null)
    local resp_msg=$(jq -r '.message' <<< "$resp_body" 2>/dev/null || echo "响应解析失败")

    # 返回结果状态码
    if [[ "$resp_code" == "200" ]]; then
        log "[${server_name}] ✔ 证书推送成功 | ID: $ssl_id | 服务端时间: ${current_time}"
        return 0
    else
        log "[${server_name}] ✘ 证书推送失败（业务码: ${resp_code:-无} | HTTP状态: ${http_code:-无响应}）"
        [[ -n "$resp_msg" ]] && log "[${server_name}] 错误详情: ${resp_msg:0:200}"
        return 1
    fi
}

# 处理单个服务器的上传流程
process_server() {
    local api_url=$1
    local api_key=$2
    local server_name=$3
    local ssl_id=$4
    
    local exit_code=1
    local attempt=1

    while : ; do
        log "[${server_name}] 尝试执行证书推送 (${attempt}/${max_retries})"
        
        if execute_api_request "$api_url" "$api_key" "$server_name" "$ssl_id"; then
            exit_code=0
            break
        fi

        if (( attempt >= max_retries )); then
            log "[${server_name}] 已达到最大重试次数 (${max_retries})"
            break
        fi

        ((attempt++))
        remaining_attempts=$(( max_retries - attempt + 1 ))
        log "[${server_name}] 等待 ${retry_interval} 秒后重试 (剩余尝试次数: ${remaining_attempts})"
        sleep "$retry_interval"
    done

    return $exit_code
}

### 主程序 ============================================================
# 初始化配置
force_mode=0                     # 强制模式标志
semi_auto_cert=0                 # 半自动模式标志（自定义证书路径）
current_window=$DEFAULT_AUTO_WINDOW  # 当前时间窗口阈值
max_retries=$DEFAULT_MAX_RETRIES # 最大重试次数
retry_interval=$DEFAULT_RETRY_INTERVAL # 重试间隔时间
declare -A SERVER_CONFIG         # 服务器配置存储

# 解析命令行参数
while getopts ":s:c:p:S:C:fm:r:i:" opt; do
  case $opt in
    s) IFS=',' read -ra SSLID_LIST <<< "$OPTARG" ;; # 改为接收逗号分隔的ID列表
    c) CERT_FILE="$OPTARG" ;;    # 可选参数：自定义证书文件路径
    p) KEY_FILE="$OPTARG" ;;     # 可选参数：自定义私钥文件路径
    S) IFS=',' read -ra selected_servers <<< "$OPTARG" ;; # 服务器列表改为数组
    C) CONFIG_FILE="$OPTARG" ;;  # 可选参数：自定义配置文件路径
    f) force_mode=1 ;;           # 可选参数：启用强制模式
    m) semi_auto_window="$OPTARG" # 可选参数：覆盖半自动模式时间窗口
       [[ $semi_auto_window =~ ^[0-9]+$ ]] || die "无效时间窗口值: $semi_auto_window" ;;
    r) max_retries="$OPTARG"     # 可选参数：设置最大重试次数
       [[ $max_retries =~ ^[0-9]+$ ]] || die "无效重试次数: $max_retries" ;;
    i) retry_interval="$OPTARG"  # 可选参数：设置重试间隔时间
       [[ $retry_interval =~ ^[0-9]+$ ]] || die "无效间隔时间: $retry_interval" ;;
    :) die "选项 -$OPTARG 需要参数" ;;
    *) die "无效选项: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

# 设置默认值
: "${CONFIG_FILE:=$DEFAULT_CONFIG_FILE}"
: "${CERT_FILE:=$DEFAULT_CERT_FILE}"
: "${KEY_FILE:=$DEFAULT_KEY_FILE}"

# 参数验证 ------------------------------------------------------------
[[ -z "${SSLID_LIST[*]}" ]] && die "必须通过 -s 参数指定SSL证书ID列表"
[[ -z "${selected_servers[*]}" ]] && die "必须通过 -S 参数指定目标服务器列表"

# 验证ID列表与服务器列表数量一致
if [[ ${#SSLID_LIST[@]} -ne ${#selected_servers[@]} ]]; then
    die "SSLID数量（${#SSLID_LIST[@]}）与服务器数量（${#selected_servers[@]}）不匹配"
fi

# 加载配置文件
[[ ! -f "$CONFIG_FILE" ]] && die "配置文件不存在: $CONFIG_FILE"
parse_config_file "$CONFIG_FILE"

# 验证服务器配置
for server in "${selected_servers[@]}"; do
    if [[ -z "${SERVER_CONFIG["${server}.api_url"]}" || -z "${SERVER_CONFIG["${server}.api_key"]}" ]]; then
        die "服务器 '$server' 配置不完整（缺少api_url/api_key）"
    fi
done

# 检测运行模式 --------------------------------------------------------
if [[ "$CERT_FILE" != "$DEFAULT_CERT_FILE" || "$KEY_FILE" != "$DEFAULT_KEY_FILE" ]]; then
    semi_auto_cert=1
    current_window=${semi_auto_window:-$DEFAULT_SEMI_AUTO_WINDOW}
    log "半自动模式激活 | 时间窗口: ${current_window}秒"
fi

# 证书文件检查 --------------------------------------------------------
for file in "$CERT_FILE" "$KEY_FILE"; do
    [[ ! -f "$file" ]] && die "证书文件不存在: $file"
    [[ ! -r "$file" ]] && die "文件不可读: $file"
done

### 时间窗口检测逻辑 ==================================================
if [[ $force_mode -eq 0 ]]; then
    current_ts=$(date +%s)
    cert_ts=$(stat -c %Y "$CERT_FILE")
    key_ts=$(stat -c %Y "$KEY_FILE")
    latest_ts=$(( cert_ts > key_ts ? cert_ts : key_ts ))

    time_diff=$(( current_ts - latest_ts ))
    if (( time_diff > current_window )); then
        formatted_time=$(TZ=$TIME_ZONE date -d "@$latest_ts" '+%Y-%m-%d %H:%M:%S %Z (UTC%:z)')
        log "证书未推送（最后修改于: $formatted_time，已过期间隔: ${time_diff}秒）"
        exit 0
    fi
else
    log "强制模式激活，跳过所有时间检测"
fi

### 证书内容处理 ======================================================
cert_content=$(jq -Rs . < "$CERT_FILE" | sed 's/^"\(.*\)"$/\1/') || die "证书内容处理失败"
key_content=$(jq -Rs . < "$KEY_FILE" | sed 's/^"\(.*\)"$/\1/') || die "私钥内容处理失败"

### 请求执行逻辑 ======================================================
overall_exit_code=0  # 初始状态为成功
for i in "${!selected_servers[@]}"; do
    server="${selected_servers[$i]}"
    ssl_id="${SSLID_LIST[$i]}"
    api_url="${SERVER_CONFIG["${server}.api_url"]}"
    api_key="${SERVER_CONFIG["${server}.api_key"]}"
    
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "开始上传到 $server (SSL ID: ${ssl_id})"
    
    if ! process_server "$api_url" "$api_key" "$server" "$ssl_id"; then
        overall_exit_code=1  # 任意一个失败即标记为失败
    fi
done

exit $overall_exit_code