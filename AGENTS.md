# IP-Sentinel 审计与修复项目

> 目标仓库：https://github.com/hotyue/IP-Sentinel
> Fork 仓库：https://github.com/aduhappy/ip-sentinel-fork（main 分支）
> 协议：AGPL-3.0

## 📍 TL;DR
- **当前阶段**：全量安全修复完成（3×P0 + 12×P1 + 多项 P2/P3），升级路径加固完毕，文档配套更新
- **下一步**：部署 main 分支生产使用，按需同步上游变更
- **最后操作**：双层仓库（外壳 + fork/ 子仓库）简化为单仓库，默认分支 main，配置推送至 aduhappy/ip-sentinel-fork
- **阻塞**：无

---

## 1. 北极星

对 IP-Sentinel 进行系统化安全审计 + fork 修复加固。产出：
- 审计报告（BUG_VERIFICATION_REPORT.md、PATCHES.md、README_BUGS.md）
- hardened 修复分支（28 个 hardened 独有 commit，覆盖全部 P0/P1 修复 + 新增功能 + 文档）

## 2. 当前状态

### 审计结果
- ✅ **3× P0**（严重）：SSRF 绕过、os.system 命令注入、HMAC 密钥用 CHAT_ID、SSRF 反转回归、OTA HMAC 降级
- ✅ **12× P1**（高危）：证书验证、OTA 签名、探针校验、SQL 注入、curl -k MITM、Nonce 耗尽、线程耗尽、Toggle 注入、CURL 数组化、OTA curl 熔断、updater 加固、agent_daemon 加固
- ✅ **9× P2**（中危）+ **5× P3**（低危）
- ✅ **全部 P0/P1 已修复**，零待办
- ✅ **所有安全修复经多方代码审查确认**
- ✅ **双层仓库已简化为单仓库**（主仓库→origin/aduhappy/ip-sentinel-fork）

### hardened 分支统计

```text
总 hardened 独有 commit:  28 个
   安全修复:              16 个 (3×P0 + 12×P1 + 1×P2)
   新功能:                 4 个 (版本追踪、备份回退、升级脚本、OTA 熔断)
   文档更新:               5 个 (README/CHANGELOG/UPGRADE_GUIDE/AGENTS)
   配置修复:               3 个 (MOD_NAME 白名单、ENABLE_MASTER_OTA、REPO_RAW_URL)
```

### 已修复（完整清单）

| 问题 | 等级 | 状态 |
|:----|:----:|:----:|
| SSRF 保护（Python ipaddress 库） | P0 | ✅ |
| SSRF 逻辑反转回归修复（! 否定符+退出码） | P0 | ✅ |
| os.system→subprocess 命令注入 | P0 | ✅ |
| HMAC 独立密钥（openssl rand -hex 32） | P0 | ✅ |
| OTA 路径 HMAC_SECRET 缺失/降级 | P0 | ✅ |
| 证书固定验证（pinnedpubkey 替代 --insecure） | P1 | ✅ |
| OTA 包 SHA256 完整性（Master+Agent 双端） | P1 | ✅ |
| 探针脚本 SHA256 校验（哈希锁定/不匹配拒绝） | P1 | ✅ |
| Toggle 注入防护（MOD_NAME 白名单） | P1 | ✅ |
| Nonce 缓存上限（OrderedDict + 100000 + 线程锁） | P1 | ✅ |
| 线程数限制（BoundedSemaphore 替代竞态 active_count） | P1 | ✅ |
| Bash word splitting（CURL_ARGS 数组化） | P1 | ✅ |
| OTA curl 下载失败熔断 + 空文件检查 | P1 | ✅ |
| Master OTA SHA256 完整性校验 | P1 | ✅ |
| updater.sh 安全加固（trap 清理 + SHA256 拒绝） | P1 | ✅ |
| agent_daemon.sh 加固（Nonce 锁 + Semaphore + query 修复） | P1 | ✅ |
| OTA 核心备份回退（core.bak 自动回滚 + TG 通知） | P1 | ✅ |
| ENABLE_MASTER_OTA 升级后默认开启 | P2 | ✅ |
| MOD_NAME 白名单移除不支持的 ota | P2 | ✅ |
| Master 追踪 Agent 版本（数据库 agent_version 列） | P2 | ✅ |
| Agent 注册携带版本号（第 8 字段） | P2 | ✅ |

### 升级路径加固
| 措施 | 状态 |
|:----|:----:|
| OTA 升级前自动备份 core → core.bak | ✅ |
| 新引擎启动 3 秒验证 + 失败自动回退 | ✅ |
| 回退后 TG 通知告警 | ✅ |
| Master OTA 增加 SHA256 完整性校验 | ✅ |
| OTA curl 失败熔断 + 空文件拒绝执行 | ✅ |
| Master 数据库追踪 Agent 版本号 | ✅ |
| 一键备份升级脚本 upgrade.sh（Master/Agent/主子同体） | ✅ |
| 升级指南 UPGRADE_GUIDE.md | ✅ |

### README/CHANGELOG 同步
| 文档 | 状态 |
|:----|:----:|
| README.md — 仓库 URL、版本号、安全特性描述 | ✅ |
| CHANGELOG.md — v4.3.3 完整更新日志 | ✅ |
| UPGRADE_GUIDE.md — 升级全流程（含回滚） | ✅ |
| AGENTS.md — 项目状态同步 | ✅ |

## 3. 任务看板

| 任务 | 状态 |
|------|:----:|
| 初版审计（32 bugs） | ✅ 完成 |
| 复审确认（5 worker 多角度审查） | ✅ 完成 |
| Fork + hardened 分支 | ✅ 完成 |
| 全部 P0（5 项）修复 | ✅ 完成 |
| 全部 P1（12 项）修复 | ✅ 完成 |
| 升级路径分析与加固 | ✅ 完成 |
| 一键备份升级脚本 upgrade.sh | ✅ 完成 |
| 双角色（Master+Agent 同体）兼容 | ✅ 完成 |
| README/CHANGELOG/UPGRADE_GUIDE 更新 | ✅ 完成 |
| AGENTS.md 项目状态同步 | ✅ 完成 |
| 上游变更同步 | ⏳ 按需 |

## 4. 铁律

1. **不改原始源码** — audit/repo/ 下的源码是只读副本
2. **修复在 main 分支上操作** — 所有安全修复已合并到 main
3. **每项修复独立 commit** — 方便上游 cherry-pick
4. **不发布 exploit** — 报告只给行号、影响描述

## 5. 路径约定

| 内容 | 存放位置 |
|------|----------|
| 审计报告 | `audit/` |
| 代码仓库（单仓库） | 根目录（origin→aduhappy/ip-sentinel-fork） |
| 上游跟踪 | `upstream` remote→hotyue/IP-Sentinel |

## 6. 环境

- 远程 origin: https://github.com/aduhappy/ip-sentinel-fork
- 上游 upstream: https://github.com/hotyue/IP-Sentinel
- 本地: G:\ip-sentinel
- 默认分支: `main`
