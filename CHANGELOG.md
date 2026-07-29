# Changelog

## [v4.3.3] - 2026-07-29

### 🔒 安全修复 (Hardened)

#### P0 — 严重
- **SSRF 保护全面升级** — 弃用正则匹配，改用 Python `ipaddress` 标准库精准验证 IPv4/IPv6 地址，覆盖私有/回环/链路本地/多播/保留/未指定地址
- **SSRF 保护逻辑反转修复** — `if !` 否定符与 Python 退出码组合错误导致保护完全反转的重大回归修复
- **命令注入防御** — 全量替换 `os.system()` 为 `subprocess.Popen` 列表参数调用，彻底消除 shell 注入
- **HMAC 独立密钥系统** — 使用 `openssl rand -hex 32` 生成独立 HMAC 密钥，废弃使用公开 CHAT_ID 签名的安全缺陷
- **OTA 升级路径 HMAC_SECRET 补充** — OTA 首次安装和版本升级时自动生成/保留 HMAC_SECRET，防止通过 OTA 路径静默降级为 CHAT_ID 签名

#### P1 — 高危
- **证书固定验证** — Agent 新增 `/cert_fp` 端点返回 SHA256 指纹，Master 优先使用 `--pinnedpubkey`，移除 `--insecure` 安全缺陷
- **OTA 包 SHA256 完整性校验** — Master 预先校验升级包哈希并传递给 Agent，Agent 下载后二次校验，不匹配即熔断
- **探针脚本 SHA256 校验** — 探针脚本下载后锁定哈希，后续更新哈希不匹配时拒绝更新
- **SQL 注入防护** — toggle handler 输入白名单验证（MOD_NAME + TARGET_STATE 双重过滤）
- **Nonce 缓存上限与线程安全** — OrderedDict 上限 100,000 + `threading.Lock` 防竞态
- **线程池限制** — 改用 `threading.BoundedSemaphore(50)` 防止资源耗尽
- **Bash word splitting 数组化** — 全部 `CURL_CMD`/`CURL_BIND_OPT` 改为 Bash 数组，消除参数注入风险
- **OTW 升级曲线失败熔断** — OTA 下载 `install.sh` 失败后发送 TG 告警并终止执行，空文件拒绝执行
- **Master OTA SHA256 校验** — 对齐 Agent OTA，Master 自升级时增加 SHA256 完整性验证
- **updater.sh 安全加固** — 添加 EXIT trap 清理临时文件、SHA256 不匹配时拒绝更新
- **agent_daemon.sh 安全加固** — webhook 进程 Nonce 锁、线程 Semaphore、query 变量越界修复
- **ENABLE_MASTER_OTA 升级后默认开启** — 修复升级后自动关闭 OTA 功能的可用性问题

### ✨ 新功能
- **Agent 升级自动备份回退** — OTA 升级前 `cp -a core core.bak`，新引擎启动失败 3 秒后自动回退旧版本并发送 TG 通知
- **Master 追踪 Agent 版本** — SQLite 数据库新增 `agent_version` 列，Master 可查看各节点升级状态
- **Agent OTA 后携带版本号注册** — Agent 升级完成后注册消息附带版本号，自动更新 Master 数据库
- **注册解析支持 8 字段格式** — 兼容旧 Agent 的同时支持版本号新字段

### ⚡ 性能优化
- **updater.sh 数组化** — 消除 word splitting 性能隐患
- **日志 TOCTOU 防护** — 日志轮转使用原子 `mv` 操作

## [v4.3.2] - 2026-07-24

### ✨ Features
- **新增重新发送注册指令** — Master 重新部署导致 Agent 节点信息丢失时，无需重新安装 Agent，直接运行 `bash /opt/ip_sentinel/core/install.sh` 选择选项 3，一键向 Telegram 推送注册命令即可恢复节点连接
- **添加布法罗地区信息** (#100)
- **注入尔湾 (Irvine) 节点** (#98)
- **扩编芝加哥 (Chicago) 节点** (#90)

### 🐛 Bug Fixes
- **修复模块化入口缺少选项3** — `install/ui_menu.sh` 同步新增重新注册功能（实际运行走此入口）
- **Telegram MarkdownV2 消息换行乱码** — `\n` 字面量改为实际换行，特殊字符正确转义

### 🎨 Improvements
- **暗黑模式星标图表修复** — 采用 GitHub 原生深色主题渲染，坐标轴不再隐形
- **升级星标趋势图引擎** — 自研渲染引擎，彻底摆脱第三方服务 502 问题

### 🔒 Security
- **添加 .gitignore** — 防止密钥泄露

## [v4.3.1] - 2026-07-24

### ✨ Features
- 分布式 VPS IP 养护系统 v4.3.1
- Master-Agent 架构，Telegram Bot 控制
- Agent 每20分钟执行养护循环（mod_google 区域模拟搜索、mod_quality IP质量探测、mod_trust 白名单访问）
- HMAC-SHA256 动态签名 60 秒有效期
- WARP 过滤、防火墙自动管理
- Python3 标准库零第三方依赖
