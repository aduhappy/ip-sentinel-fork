# IP-Sentinel 审计与修复项目

> 目标仓库：https://github.com/hotyue/IP-Sentinel
> Fork 仓库：https://github.com/aduhappy/ip-sentinel-fork（main 分支）
> 协议：AGPL-3.0

## 📍 TL;DR
- **当前版本**：`4.3.2-hardened.6`（Master / Agent 同号，见 `version.txt`）
- **当前阶段**：第二轮安全复审修复完成并已并入 main（2026-09-29 ~ 10-01，详见 §2.2）
- **下一步**：真机验证一次完整升级链路（先升 Master → 全舰队 OTA → 换 Bot 凭证），按需同步上游
- **使用者**：仅仓库所有者本人使用私有中枢模式；测试通过即可直接合并 main
- **阻塞**：无

---

## 1. 北极星

对 IP-Sentinel 进行系统化安全审计 + fork 修复加固，产出可直接部署的加固版 main 分支，并保持对存量节点的无缝升级。

## 2. 当前状态

### 2.1 第一轮（2026-07，原 hardened 分支，已并入 main）

- ✅ 3× P0：SSRF 绕过与逻辑反转回归、`os.system` 命令注入、HMAC 独立密钥、OTA 路径 HMAC 降级
- ✅ 12× P1：证书固定、OTA 包 SHA256、探针哈希锁、SQL/Toggle 注入、Nonce 上限与线程锁、线程数限制、CURL 数组化、OTA 下载熔断、updater/agent_daemon 加固、OTA core.bak 回退
- ✅ 9× P2 + 5× P3；`upgrade.sh` 一键备份升级；README/CHANGELOG/UPGRADE_GUIDE
- 审计报告（BUG_VERIFICATION_REPORT.md、PATCHES.md、README_BUGS.md）存放在本地 `audit/`，已被 `.gitignore` 排除，**不在仓库中**

### 2.2 第二轮复审（2026-09-29 ~ 10-01）

复审发现第一轮的若干修复只完成了一半，以及新的高危问题。全部已修复、测试、并入 main：

| 问题 | 等级 | 提交 | 版本 |
|:----|:----:|:----:|:----:|
| HMAC 签名不覆盖查询参数（可篡改 key/sha256/mod/b64） → v2 全参数签名 | P0 | `3f6f8d16` | .1 |
| OTA `sha256` 缺失时跳过校验 → 必填 | P1 | `97f5cf1a` | .1 |
| 升级销毁 TLS 证书 → 升级后 Master 证书固定失配、全部指令 FAILED | P1 | `23c8096d` | .1 |
| 升级清空 `.probe_hash`，探针哈希锁失效 | P1 | `23c8096d` | .1 |
| 安装自检只查 2/8 个核心文件 | P2 | `398aa0b3` | .1 |
| OTA 锁定到提交 SHA（防 Raw 缓存新旧混装） | 加固 | `ea103d36` | .1 |
| OTA 读取 REPO_RAW_URL 未去行尾换行（潜伏） | P3 | `f94d205d` | .1 |
| 版本号统一为 `<上游基线>-hardened.<n>` | 维护 | `31cd8d4d` | .1 |
| 注册解析第 7 字段吞并版本号 → `truehardened`，节点被全舰队 OTA 漏掉 | P1 | `3668d71c` | .2 |
| 首次握手依赖公开的 CHAT_ID → 配对密钥 + 注册暗号携带证书指纹 | P0 | `f76a074d` | .2 |
| 启动密钥收敛使用空 CHAT_ID，从未生效 | P1 | `2f9fa51a` | .3 |
| **私有中枢响应任意会话 → 陌生人注册节点即可骗取全局 HMAC_SECRET** → 所有者锁定 | P0 | `3bc5164f` | .3 |
| 移植上游 #102 全舰队切换 Bot 凭证（按 fork 安全模型改造） | 功能 | `5121a8ab` | .4 |
| README 如实说明加固范围、公共网关数据流向、对外连接 | 文档 | `8dfd9f93` | .4 |
| 回执被拼接 FAILED 致 OTA 汇总虚增失败条目；`Request Expired` 时钟偏差提示 | P2 | `059938ae` | .5 |
| 司令部选择养护 IP（v4 / v6 / 双栈轮流）+ 全舰队汇总简报（每日北京 0:00） | 功能 | `e801e063` | .6 |

### 2.3 关键机制速查（改代码前必读）

- **版本号**：`<上游基线>-hardened.<n>`，基线为分叉时上游 4.3.2；`sort -V` 下 `4.3.2 < 4.3.2-hardened.1 < 4.3.3`。Master 首页/战报以 `!=` 判断新版本，发版须同步修改 `version.txt` 与 5 个安装入口的兜底版本（`install.sh`、`master/install_master.sh`、`install/master_setup.sh`、`install/env_setup.sh`、`core/install.sh`）。
- **签名 v2**：`HMAC(key, "v2:<路径>?<按 & 拆分、去空、字节序排序后的业务参数>:<t>")`。Master `canonical_query` 与 Agent `biz_params` 必须同算法。Agent 仅对**无业务参数**的请求接受 v1（`<路径>:<t>`）。Master 仅在 `401 Unauthorized` 时降级：v2+主密钥 → v2+CHAT_ID → v1+主密钥 → v1+CHAT_ID。
- **Agent 验签密钥优先级**：`HMAC_SECRET` > `PAIR_KEY` > `CHAT_ID`（仅无 PAIR_KEY 的旧节点）。`/setkey`、`/cert_fp` 额外接受 `PAIR_KEY`（支持 Master 重装后重新配对）；`/setkey` 在 `AUTH_TOKEN == CHAT_ID` 时额外接受 CHAT_ID（旧节点引导）。
- **注册暗号**：`#REGISTER#|地区|节点|IP|端口|别名|OTA|版本|PAIR_KEY|证书指纹`。第 9、10 字段仅私有模式且已有 PAIR_KEY 时追加；官方公共网关模式保持 8 字段。生成点共 4 处：`core/install.sh`（首装/升级、重发选项 3）、`install/ui_menu.sh`（同上）。
- **PAIR_KEY 生成规则**：首装（私有模式）生成；升级仅当 `HMAC_SECRET` 非空时补发（CHAT_ID 态节点若补发会切换验签密钥而失联）。
- **所有者锁定**：`master.conf` 的 `OWNER_CHAT_ID`；来源依次为安装时填写 → 升级时库中唯一节点会话 → 空库首个会话；多会话时拒绝一切请求。轮询批次跑在管道子 shell 中，跨批次状态必须落盘到 `master.conf`。
- **Master 启动时 `$CHAT_ID` 为空**（`master.conf` 不含 CHAT_ID），启动阶段需要会话 ID 时必须从数据库按节点取。
- **webhook.py 的 `do_GET`**：函数内任何 `import X` 都会让 X 成为整个函数的局部名。不要在其中写 `import urllib.xxx`（会遮蔽顶层 `urllib`，所有请求报错）；用到 `re` 的分支须自行 `import re`。
- **升级保留文件**：`core/` 整体替换前迁移 `cert.pem`、`key.pem`、`.probe_hash`、`ip_probe.sh`（两条安装路径各一处）。
- **养护地址族**：`config.conf` 的 `MAINT_FAMILY`（空 / `4` / `6` / `dual`）与 `PUBLIC_IP4`、`BIND_IP4`、`PUBLIC_IP6`、`BIND_IP6`，由 `/trigger_ipmode` 写入；**不改动**原单栈的 `PUBLIC_IP` / `BIND_IP` / `IP_PREF`（`tg_report.sh`、`mod_quality.sh` 仍使用它们）。`mod_google.sh` / `mod_trust.sh` 读取配置后就地覆盖这三个变量，dual 时各自用 `core/.family_google`、`core/.family_trust` 轮流。日志模块名 `Google4/6`、`Trust4/6`。
- **汇总简报**：Agent `/report_data` 只读配置与近 24 小时日志（不发外部请求），并写 `core/.master_polled`；`tg_report.sh` 无 `--manual` 时若该文件 26 小时内更新过则跳过推送（`/trigger_report` 传 `--manual`）。节点定时战报为 UTC 16:10，司令部汇总为 UTC 16:00（`MASTER_DIR/.daily_summary` 记当日已发）。汇总消息按 UTF-16 码元计长分段（上限 3800）。
- **司令部发送含 `%`、`&` 的文本**用 `send_json_text`（JSON），`send_msg` 是表单编码，`%0A` 才是换行，`&` 会截断。
- **OTA 必须逃出守护服务 cgroup**：安装程序会 `systemctl kill` 守护服务，同 cgroup 的升级进程会被连带杀掉。Agent 用 `systemd-run` 拉起升级脚本；`core/install.sh` 在 `SILENT_OTA` 下检测 `/proc/self/cgroup`，仍在守护服务内则复制自身经 `systemd-run` 转移（`OTA_ESCAPED=1` 防重入）。**不要**把 OTA 启动方式改回普通子进程。
- **"OTA 受理成功"≠ 升级完成**：只表示节点接受了指令；以节点发回的「引擎热更新完成」为准。

### 2.4 测试方式

仓库内暂无测试目录。第二轮所有改动均在本地沙箱验证：从 `core/agent_daemon.sh` 抽取 `webhook.py`（`/opt/ip_sentinel` 下放临时证书与配置）真实运行，从 `master/tg_master.sh` 抽取 `canonical_query` / `generate_signed_url` / `call_agent` 等函数与代码块对其发请求；Telegram 接口用本地假服务替代（仅改测试副本中的 `api.telegram.org`）。覆盖：签名 20 项、OTA 9 项、配对握手 17 项、所有者锁定 14 项、换 Bot 凭证 Agent 17 项 / Master 13 项；双栈与汇总：`/trigger_ipmode` 11 项（PATH 注入假 `ip`/`curl` 模拟 v6 正常 / WARP / 无路由）、`/report_data` 9 项（按真实日志格式构造）、模块地址族选择、`tg_report.sh` 去重与分族 6 项、Master 菜单与切换 12 项、控制台与每日触发 6 项、汇总分段（120 节点按 UTF-16 计长）与真实签名端到端拉取。**尚未在真实 VPS + 真实 Telegram 上跑过完整链路。**

### 2.5 已知限制 / 未做

- **官方公共网关模式**：节点保留 CHAT_ID 验签（官方司令部以 CHAT_ID 签名），fork 加固不生效；官方司令部签名格式与 v2 不同，其「开关」「改名」指令会被拒绝（可选：让公共模式 Agent 额外接受上游签名格式，该格式同样覆盖参数）。
- **无证书指纹的旧节点**：Master 仍以 `--insecure` 连接（新注册节点已从首个请求起固定证书）。
- **HMAC_SECRET 全局唯一**：所有者锁定后风险已收敛；如需进一步隔离可改为每节点独立密钥。
- **供应链信任根是 GitHub 仓库本身**：哈希与提交锁定防传输篡改与版本混装，不防仓库被攻破（需发布签名方案）。

## 3. 任务看板

| 任务 | 状态 |
|------|:----:|
| 第一轮审计与 P0/P1 修复（原 hardened 分支） | ✅ 完成 |
| 第二轮复审：签名/OTA/证书/握手/所有者锁定 | ✅ 完成 |
| 版本号方案 `-hardened.<n>` | ✅ 完成 |
| 移植上游 #102 换 Bot 凭证 | ✅ 完成 |
| README 公共网关数据流向说明 | ✅ 完成 |
| 司令部选择养护 IP（双栈）+ 汇总简报 | ✅ 完成 |
| 真机验证完整升级链路 | ⏳ 待做 |
| 上游变更同步（上游 v4.3.3~4.3.5 的 UI 改动未移植） | ⏳ 按需 |
| 公共网关模式签名兼容 | 💤 可选 |

## 4. 铁律

1. **不改原始源码** — `audit/repo/` 下的源码是只读副本（本地目录，不在仓库中）
2. **修复在 main 分支上操作** — 开发分支测试通过后直接合并 main
3. **每项修复独立 commit** — 方便上游 cherry-pick
4. **不发布 exploit** — 报告只给行号、影响描述
5. **每次发版必须升版本号** — 否则存量节点不会提示升级（见 §2.3）
6. **存量节点必须能无缝升级** — 任何协议改动都要考虑新旧 Master/Agent 混跑

## 5. 路径约定

| 内容 | 存放位置 |
|------|----------|
| 审计报告 | `audit/`（本地，已 gitignore） |
| 代码仓库（单仓库） | 根目录（origin→aduhappy/ip-sentinel-fork） |
| 上游跟踪 | `upstream` remote→hotyue/IP-Sentinel（需自行 `git remote add`） |
| 升级说明 / 兼容矩阵 | `UPGRADE_GUIDE.md` §7.1 |

## 6. 环境

- 远程 origin: https://github.com/aduhappy/ip-sentinel-fork
- 上游 upstream: https://github.com/hotyue/IP-Sentinel
- 本地: G:\ip-sentinel（第二轮在 Claude Code 云端会话中完成）
- 默认分支: `main`
