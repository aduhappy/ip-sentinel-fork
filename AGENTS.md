# IP-Sentinel 审计与修复项目

> 目标仓库：https://github.com/hotyue/IP-Sentinel
> Fork 仓库：https://github.com/aduhappy/ip-sentinel-fork（hardened 分支）
> 协议：AGPL-3.0

## 📍 TL;DR
- **当前阶段**：初版审计完成（32 bug）+ 安全修复已完成 7 项（3×P0 + 3×P1 + 1×P1）
- **下一步**：部署使用 hardened 分支，持续同步上游变更
- **阻塞**：无

---

## 1. 北极星

对 IP-Sentinel 进行系统化安全审计 + fork 修复加固。产出：
- 审计报告（BUG_VERIFICATION_REPORT.md、PATCHES.md、README_BUGS.md）
- hardened 修复分支（含 4 个修复 commit，覆盖 P0-001/002/003 + P1-001/005/006/012）

## 2. 当前状态

### 审计结果
- ✅ **3× P0**（严重）：SSRF 绕过、os.system 命令注入、HMAC 密钥用 CHAT_ID
- ✅ **15× P1**（高危）：SQL 注入、curl -k MITM、探针校验、Nonce 耗尽、线程耗尽、OTA 供应链等
- ✅ **9× P2**（中危）+ **5× P3**（低危）
- ✅ **已修复 7 项**：P0-001 SSRF、P0-002 os.system、P0-003 HMAC、P1-001 toggle 注入、P1-005 Nonce、P1-006 线程、P1-012 数组化

### 已修复
| 问题 | 等级 | 修复方式 |
|:----|:----:|---------|
| SSRF 保护（ipaddress 库） | P0 | 正则→Python3 ipaddress |
| os.system 命令注入 | P0 | 全部改为 subprocess.Popen |
| HMAC 独立密钥 | P0 | openssl rand -hex 32 + 双轨兼容 |
| toggle 注入防护 | P1 | MOD_NAME 白名单 + TARGET_STATE 过滤 |
| Nonce 缓存上限 | P1 | OrderedDict + 100000 上限 |
| 线程数上限 | P1 | max_threads=50 |
| Bash word splitting | P1 | CURL_BIND_OPT→数组 |

### 待修复
| 问题 | 等级 | 难度 |
|:----|:----:|:----:|
| P1-002 证书验证（curl -k→pinnedpubkey） | P1 | 中等 |
| P1-003 探针 SHA256 校验 | P1 | 中等 |
| P1-008 OTA 签名验证 | P1 | 中等 |
| P2/P3 代码质量 | P2-3 | 简单 |

## 3. 任务看板

| 任务 | 状态 |
|------|:----:|
| 初版审计（32 bugs） | ✅ 完成 |
| 复审确认 | ✅ 完成 |
| Fork + hardened 分支 | ✅ 完成 |
| P0-001 SSRF 修复 | ✅ 完成 |
| P0-002 os.system→subprocess | ✅ 完成 |
| P0-003 HMAC 独立密钥 | ✅ 完成 |
| P1-001 toggle 注入防护 | ✅ 完成 |
| P1-005 Nonce 缓存限制 | ✅ 完成 |
| P1-006 线程数限制 | ✅ 完成 |
| P1-012 数组化 | ✅ 完成 |
| P1-002 证书验证 | ⏳ 待办 |
| P1-003 探针校验 | ⏳ 待办 |
| P1-008 OTA 签名 | ⏳ 待办 |
| 剩余 P2/P3 修复 | ⏳ 低优先级 |

## 4. 铁律

1. **不改原始源码** — audit/repo/ 下的源码是只读副本
2. **修复在 fork/ 下操作** — hardened 分支存放所有安全修复
3. **每项修复独立 commit** — 方便上游 cherry-pick
4. **不发布 exploit** — 报告只给行号、影响描述

## 5. 路径约定

| 内容 | 存放位置 |
|------|----------|
| 审计报告 | `audit/` |
| 代码仓库（fork） | `fork/`（对接 GitHub hardened 分支） |
| 上游跟踪 | `fork/.git` upstream remote |

## 6. 环境

- Fork: https://github.com/aduhappy/ip-sentinel-fork
- 上游: https://github.com/hotyue/IP-Sentinel
- 本地: G:\ip-sentinel
