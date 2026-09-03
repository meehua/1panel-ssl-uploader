# 1Panel SSL Uploader

一个用于 1Panel 之间同步 SSL 证书的 Go 工具，也可以用于手动上传证书到 1Panel，适合配合定时任务或证书签发后的自动执行流程。

这个版本已经改写为纯 Go 实现，运行时不再依赖 `curl`、`jq`、`md5sum` 等外部命令，直接编译成一个独立二进制即可使用。

## 构建

```bash
go build -o ssl_upload .
```

## 测试

```bash
go test ./...
```

## 使用

### 自动模式

默认读取当前目录下的 `./fullchain.pem` 和 `./privkey.pem`，如果两个文件在最近 5 秒内发生变化就执行上传。

```bash
./ssl_upload -s 12,23 -S server1,server2
```

### 半自动模式

只要显式指定了证书或私钥路径，就会进入半自动模式。默认允许文件在最近 86400 秒内发生变化，可用 `-m` 覆盖。

```bash
./ssl_upload -s 123 -S server1 -c /path/to/cert.pem -p /path/to/key.pem
```

### 强制模式

```bash
./ssl_upload -s 123 -S server1 -f
```

## 参数

| 参数 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-s` | 是 | 无 | 目标 SSL 证书 ID 列表，多个 ID 用逗号分隔 |
| `-S` | 是 | 无 | 目标服务器名称列表，多个名称用逗号分隔，顺序必须与 `-s` 对应 |
| `-c` | 否 | `./fullchain.pem` | 证书文件路径 |
| `-p` | 否 | `./privkey.pem` | 私钥文件路径 |
| `-C` | 否 | 当前目录下的 `config.json` | 配置文件路径 |
| `-f` | 否 | 关闭 | 强制模式，跳过更新时间检测 |
| `-m` | 否 | `86400` | 半自动模式时间窗口，单位秒 |
| `-r` | 否 | `8` | 最大重试次数 |
| `-i` | 否 | `15` | 重试间隔，单位秒 |

## 配置文件

配置格式与原脚本保持一致：

```json
{
  "version": 1,
  "servers": {
    "server1": {
      "url": "https://panel1.example.com",
      "token": "your-api-token1",
      "api_version": 2
    },
    "server2": {
      "url": "https://panel2.example.com",
      "token": "your-api-token2",
      "api_version": 1
    }
  }
}
```

说明：

- `api_version` 不填时默认使用 `2`。
- `version` 目前固定为 `1`。
- 建议把 `config.json` 权限设为 `600`。

## 时区

描述信息和时间窗口日志默认使用 `Asia/Shanghai`。如果需要，可以通过 `TIME_ZONE` 环境变量指定其他时区。

## 说明

- 证书上传失败时会自动重试。
- 如果首次 HTTPS 校验失败，程序会自动尝试跳过证书校验重试一次。
- 仓库中保留的 `script.sh` 仅作为历史参考，新版本建议直接使用 Go 二进制。

## 详细教程

- [适用于 1Panel 之间的 SSL 证书同步更新脚本](https://www.l0u0l.com/posts/1panel-ssl-uploader/)