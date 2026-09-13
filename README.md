# 中国 IP 域名分类器

基于 **DNS 解析 + GeoLite2 GeoIP 数据库** 的高并发域名分类工具。输入一批域名，自动解析出 IP 并判断是否属于中国大陆（含港澳台），同时区分根域名与子域名，结果实时写入分类文件。

## 功能特性

- **异步高并发 DNS 解析**：内置多组 DNS 服务器、超时与重试机制，稳定高速
- **GeoIP 国家判断**：基于 MaxMind GeoLite2-Country 数据库，精确到国家/地区
- **中国地区识别**：将 `CN` / `HK` / `MO` / `TW` 统一归类为「中国」
- **根域名 / 子域名分类**：基于公共后缀列表（tldextract）区分，`www` 前缀按子域名处理
- **实时写盘**：结果边处理边落盘（1 秒 flush、60 秒 fsync），不怕中途丢失
- **DNS 缓存**：内存缓存已解析域名（上限 50 万条），避免重复查询
- **断点续跑**：自动记录已处理域名，中断后重跑自动跳过
- **安全退出**：`Ctrl+C` / `SIGTERM` 优雅停止，先落盘再退出
- **数据库自动下载**：本地无 mmdb 时自动从镜像下载

## 环境要求

- Python 3.6+
- Linux / macOS / Windows（需可用的 `curl`）

## 安装依赖

```bash
pip3 install -r requirements.txt
```

依赖（见 [requirements.txt](./requirements.txt)）：`aiodns`、`geoip2`、`tldextract`。

> `aiodns` 依赖 `pycares`（C 扩展）。安装时报编译错误时：
> - **macOS**：先执行 `xcode-select --install`
> - **Debian/Ubuntu**：先安装 `sudo apt install build-essential`

## 使用方法

### 基本用法

```bash
python3 cn.py -f 域名列表.txt
```

### 指定并发数

```bash
python3 cn.py -f success.txt -t 1000
```

### 指定 GeoIP 数据库路径

```bash
python3 cn.py -f success.txt -t 1000 -m /path/to/GeoLite2-Country.mmdb
```

### 命令行参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `-f, --file` | 输入域名文件（必填） | — |
| `-t, --threads` | 并发数量 | `2000`（上限 `10000`） |
| `-m, --mmdb` | GeoLite2-Country.mmdb 路径 | `GeoLite2-Country.mmdb` |

## 输入文件格式

每行一个域名，支持以下格式（会自动清洗成纯域名）：

```text
example.com
www.example.com
http://example.com/a
https://example.com:8080/path
```

## 输出文件

运行结束后会在当前目录生成以下文件：

| 文件 | 说明 |
| --- | --- |
| `china_tld.txt` | 中国根域名（如 `example.com`） |
| `china_sub.txt` | 中国子域名（如 `a.example.com`、`www.example.com`） |
| `other_tld.txt` | 其他国家/地区根域名 |
| `other_sub.txt` | 其他国家/地区子域名 |
| `failed_domains.txt` | 解析失败 / 无法分类的域名 |
| `processed_domains.txt` | 已处理域名记录（用于断点续跑） |

## 工作原理

1. 读取输入文件并清洗出合法域名
2. 异步 DNS 解析为 IPv4 地址（命中缓存则跳过查询）
3. 用 GeoLite2-Country 查询 IP 归属国家/地区
4. 判断是否属于 `CN` / `HK` / `MO` / `TW`（统一视为「中国」）
5. 用 tldextract 区分根域名与子域名
6. 实时写入对应分类文件

## 配置项

以下参数位于 `cn.py` 顶部「配置」区域，可按需调整：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `DNS_SERVERS` | `223.5.5.5`、`119.29.29.29`、`8.8.8.8`、`1.1.1.1` | DNS 服务器列表 |
| `CHINA_COUNTRIES` | `CN` / `HK` / `MO` / `TW` | 视为「中国」的国家/地区代码 |
| `DNS_TIMEOUT` | `1.5` | DNS 超时（秒） |
| `DNS_RETRIES` | `2` | DNS 重试次数 |
| `DNS_CACHE_MAX` | `500000` | DNS 缓存上限 |

## GeoIP 数据库

工具使用 MaxMind 的 GeoLite2-Country 数据库。仓库已内置一份 `GeoLite2-Country.mmdb`；若缺失，脚本会尝试自动从镜像下载（`cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/`），也可用 `-m` 手动指定路径。

> 版权说明：GeoLite2 数据库由 MaxMind 创建，依据 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可发布，使用时需保留 MaxMind 署名。

## 常见问题

- **报 `Could not contact DNS servers`**：并发过高触发本机/DNS 限流，调低 `-t` 即可。
- **`aiodns` 安装失败**：缺编译工具，见上文「安装依赖」。
- **只想判断中国大陆、不含港澳台**：把 `CHINA_COUNTRIES` 改为仅 `{"CN"}`。
