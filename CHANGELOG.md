# Changelog

## [v4.3.2-hardened.2] - 2026-10-01

### 🔒 安全修复 (Hardened)
- **首次握手不再依赖公开的 CHAT_ID（配对密钥）** — 此前新节点在收到 `/setkey` 前以 `CHAT_ID` 作为验签密钥，知道"IP + 端口 + CHAT_ID"的人即可抢先下发自己的密钥接管节点，且密钥经 `--insecure` 连接下发。现 Agent 安装时生成 `PAIR_KEY`，与本机 TLS 公钥指纹一起作为注册暗号第 9、10 字段经用户 Telegram 会话交给 Master：Master 以 `PAIR_KEY` 签名、固定暗号中的证书后下发 `HMAC_SECRET`，新装节点全程不接受 `CHAT_ID`
- **Master 重装后可凭注册暗号重新配对** — Agent 对 `/setkey`、`/cert_fp` 始终接受 `PAIR_KEY` 签名；此前已轮换密钥的节点在 Master 重装后只能重装 Agent
- **存量 CHAT_ID 态节点自动收敛** — Master 每次启动在后台对已固定证书的节点用 `CHAT_ID` 引导下发 `HMAC_SECRET`（已轮换节点以 401 拒收，无副作用），密钥不在未校验证书的连接上发出
- **注册确认回显握手方式**，便于识别仍走旧握手的节点
- **模块化安装路径的注册暗号补齐版本号字段**（此前缺第 8 字段）

### 🐛 Bug Fixes
- **注册解析把版本号并入 OTA 字段** — Master 按 7 个变量拆分注册暗号，第 7 字段 (OTA) 会吞下 `true|版本号`；旧版本号全为数字时恰好被过滤掉，`4.3.2-hardened.1` 含字母后会存成 `truehardened`，节点被全舰队 OTA 漏掉。现按位拆分全部字段，并在 Master 启动时自愈已被污染的记录

## [v4.3.2-hardened.1] - 2026-10-01

> **版本号说明**：fork 版本号改为 `<上游基线>-hardened.<序号>`，基线为分叉时的上游 v4.3.2，避免与上游 v4.3.3~v4.3.5（内容不同）重名。`sort -V` 下 `4.3.2 < 4.3.2-hardened.1 < 4.3.2-hardened.2 < 4.3.3`，现有 v4.3.1/v4.3.2 节点会被识别为可升级。
> **升级顺序**：先升级 Master（首页「升级控制中枢」按钮），再全舰队 OTA；若先用旧 Master OTA 了 Agent，旧 Master 的带参指令（OTA/开关/改名）会被拒绝，升级 Master 后即恢复，不会失联。

### 🔒 安全修复 (Hardened)
- **HMAC 签名覆盖全部查询参数（v2 签名）** — 旧签名仅覆盖 `路径:时间戳`，`/setkey` 的 `key`、`/trigger_ota` 的 `sha256`、`/trigger_toggle` 的 `mod/state`、`/trigger_rename` 的 `b64` 均可被中间人篡改（例如删除 `sha256` 使 OTA 跳过完整性校验）。v2 签名改为 `v2:路径?排序后全部业务参数:时间戳`，Master/Agent 同算法规范化；新 Agent 仅对无业务参数的请求保留 v1 兼容，Master 在 401 时自动降级以保证旧 Agent 仍可 OTA 升级（对应上游 #108，覆盖范围更完整）
- **call_agent 网络失败不再重复降级重试** — 仅验签失败时回退，避免离线节点重复等待超时
- **OTA 完整性哈希改为必填** — Agent 收到不带（或格式非法的）`sha256` 的 OTA 指令直接 400 拒绝，不再"跳过校验照常升级"；Master 无法从仓库拉取 `install.sh` 计算哈希时中止下发并告警，而非发送无校验的 OTA
- **OTA 锁定到提交 SHA** — Master 下发 OTA 前经 GitHub API 解析分支当前提交，`install.sh` 哈希与 Agent 端全部文件（核心脚本、版本号、数据）均从该不可变提交拉取，杜绝 GitHub Raw 约 5 分钟缓存造成的新旧文件混装，TG 播报同时显示锁定的提交号便于核对；API 不可达或自建镜像时自动回退为分支地址。Master 校验用临时文件改用 `mktemp`，不再使用固定 `/tmp` 路径

### 🐛 Bug Fixes
- **升级后 Master 与节点失联（证书固定失配）** — 两条安装路径（`core/install.sh` 与模块化 `install/sys_daemon.sh`）升级时都会销毁 TLS 证书并整体替换 `core/` 目录，Agent 重铸新证书后与 Master 已固定的公钥指纹不符，所有指令 `FAILED`，直至手动转发新的注册暗号。现升级不再销毁证书，并在替换核心目录前迁移 `cert.pem`/`key.pem`；v4.2.2 前的陈旧证书仍由 `agent_daemon.sh` 按签发日期自动重铸
- **探针哈希锁随升级失效** — 同一原因导致 `.probe_hash` 与已锁定的 `ip_probe.sh` 每次升级被清空，锁定机制退化为重新信任首次下载；现一并迁移
- **核心模块自检仅覆盖 2/8 个文件** — 安装/升级时只校验 `runner.sh` 与 `agent_daemon.sh` 非空，其余 6 个模块下载失败或被截断仍会覆盖上线；现对全部 8 个核心文件做非空 + `bash -n` 语法检查，任一不通过即中止覆写、保留旧版
- **OTA 读取 REPO_RAW_URL 未去除行尾换行** — 导致结尾引号残留、OTA 脚本引号错位（潜伏缺陷，仅当 `/opt/ip_sentinel/core/install.sh` 存在时触发）

## [v4.3.2-hardened.0] - 2026-07-29

> fork 首轮安全加固。当时 `version.txt` 未随之更新，节点仍显示 v4.3.1/v4.3.2；此前文档中的 "v4.3.3" 均指此版本，与上游 v4.3.3 无关。

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
