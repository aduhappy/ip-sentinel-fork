# IP-Sentinel 升级指南 — hardened 安全增强分支

> **本文档面向已部署原版 IP-Sentinel 的用户，指导如何将 1 个 Master + 5 个 Agent 升级到安全加固的 `hardened` 分支。**
>
> **先升级 Master，再升级 Agent** — 旧 Master 发 HTTP 明文请求，新 Agent 强制 HTTPS+HMAC 验证，顺序不可颠倒。

---

## 1. 概述

### 1.1 hardened 分支 vs 原版

| 维度 | 原版 (hotyue/IP-Sentinel) | hardened (aduhappy/ip-sentinel-fork) |
|---|---|---|
| **代码基础** | 上游主线 v4.3.x | 基于上游的 fork，追加 20+ 安全修复 |
| **安全修复** | 无系统审计 | 3×P0 + 12×P1 + 多 P2/P3，全栈零信任加固 |
| **升级回退** | 无 | 升级前自动备份 `core.bak`，启动失败 3 秒回退 |
| **版本追踪** | 无 | Master 数据库记录 Agent `agent_version` |
| **安装源** | `hotyue/IP-Sentinel/main` | `aduhappy/ip-sentinel-fork/hardened` |

### 1.2 hardened 安全修复清单

| 等级 | 修复项 | 文件 | 状态 |
|:----:|--------|------|:----:|
| **P0** | SSRF 保护 — Python `ipaddress` 库全面验证 | `master/tg_master.sh` | ✅ 已修复 |
| **P0** | SSRF 逻辑反转回归修复 — `!` 否定符与退出码组合错误 | `master/tg_master.sh` | ✅ 已修复 |
| **P0** | 命令注入 — `os.system()` → `subprocess.Popen` 列表参数 | `core/agent_daemon.sh` | ✅ 已修复 |
| **P0** | HMAC 独立密钥 — `openssl rand -hex 32` 替代 CHAT_ID | `core/agent_daemon.sh` + Master | ✅ 已修复 |
| **P0** | OTA 路径 HMAC_SECRET 缺失 — 升级时自动生成/保留 | `core/install.sh` | ✅ 已修复 |
| **P1** | 证书固定验证 — `--pinnedpubkey` 替代 `--insecure` | `master/tg_master.sh` | ✅ 已修复 |
| **P1** | OTA 包 SHA256 完整性 — Master 预校验 + Agent 二次校验 | `core/agent_daemon.sh` | ✅ 已修复 |
| **P1** | 探针脚本 SHA256 校验 — 哈希锁定，不匹配拒绝 | `core/updater.sh` + `mod_quality.sh` | ✅ 已修复 |
| **P1** | Toggle 注入 — MOD_NAME 白名单 + TARGET_STATE 过滤 | `master/tg_master.sh` | ✅ 已修复 |
| **P1** | Nonce 缓存上限 — `OrderedDict` + 100,000 + `threading.Lock` | `core/agent_daemon.sh` | ✅ 已修复 |
| **P1** | 线程限制 — `BoundedSemaphore(50)` 替代竞态 `active_count()` | `core/agent_daemon.sh` | ✅ 已修复 |
| **P1** | Bash word splitting 数组化 — `CURL_ARGS` 数组防注入 | `core/tg_report.sh` + `updater.sh` | ✅ 已修复 |
| **P1** | OTA curl 失败熔断 — 下载失败发告警 + 空文件拒绝执行 | `core/agent_daemon.sh` | ✅ 已修复 |
| **P1** | Master OTA SHA256 校验 — 对齐 Agent OTA 安全级别 | `master/tg_master.sh` | ✅ 已修复 |
| **P1** | updater.sh 加固 — trap 清理 + SHA256 拒绝 | `core/updater.sh` | ✅ 已修复 |
| **P1** | agent_daemon.sh 加固 — Nonce 锁 + Semaphore + query 修复 | `core/agent_daemon.sh` | ✅ 已修复 |
| **P1** | OTA 核心备份回退 — `core.bak` 备份 + 自动回滚 | `core/install.sh` | ✅ 已修复 |
| **P1** | ENABLE_MASTER_OTA 默认 `true` — 升级后不自动关闭 | `install/master_setup.sh` | ✅ 已修复 |
| **P2** | Master 追踪 Agent 版本 — 数据库 `agent_version` 列 | `master/tg_master.sh` | ✅ 已修复 |
| **P2** | Agent 注册携带版本号 — 第 8 字段 | `core/install.sh` | ✅ 已修复 |
| **P2** | Toggle 白名单清理 — 移除不支持的 `ota` | `master/tg_master.sh` | ✅ 已修复 |

---

## 2. 升级前准备

### 2.1 备份（必须执行）

```bash
# Master
sudo cp -ra /opt/ip_sentinel_master /opt/ip_sentinel_master.bak.$(date +%Y%m%d)

# 每个 Agent（逐台执行）
sudo cp -ra /opt/ip_sentinel /opt/ip_sentinel.bak.$(date +%Y%m%d)
```

### 2.2 检查当前版本

```bash
# Master
grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf 2>/dev/null

# Agent（任选一台）
grep "^AGENT_VERSION=" /opt/ip_sentinel/config.conf 2>/dev/null

# hardened 分支最新版本
curl -sfL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/version.txt
```

### 2.3 前置条件检查

```bash
# 环境检查
command -v python3 && command -v openssl && command -v curl && command -v sqlite3

# 网络连通
curl -sfL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/version.txt

# 确认当前安装源
grep "REPO_RAW_URL" /opt/ip_sentinel_master/tg_master.sh 2>/dev/null
```

---

## 3. 升级 Master

### 3.1 SSH 升级（推荐）

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/master/install_master.sh)"
```

**交互过程：**
```
检测到已部署 → "是否按原配置直接进行平滑升级？(y/n, 默认y):" → 回车
"是否保留历史节点数据库？(y/n, 默认y):" → 回车
```

升级自动完成，约 3-5 秒。旧 Agent 通过 HMAC 双轨兼容（回退 `CHAT_ID`）继续正常工作。

### 3.2 升级后验证

```bash
# 版本
grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf
# 预期: MASTER_VERSION="4.3.1"

# 发送 /start 给 Bot，确认菜单正常显示
```

---

## 4. 升级 Agent（5 台）

### 4.1 方案 A：逐台 SSH（推荐，5 台以下）

每台 Agent 逐台执行：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/install.sh)"
```

**交互过程：**
```
"是否按原配置直接进行平滑升级？(y/n, 默认y):" → 回车
```

升级过程约 10-20 秒。脚本会自动：
1. source 旧配置（保留 `TG_TOKEN`、`CHAT_ID`、`NODE_NAME` 等）
2. 补充新字段：`HMAC_SECRET`（旧版升级时生成）、`ENABLE_OTA` 等
3. 备份 `core` → `core.bak`
4. 下载新核心文件 → 替换 → pkill 旧进程 → 重启
5. 3 秒后验证新引擎存活，成功则删备份，失败则自动回退

### 4.2 方案 B：TG OTA 静默升级（Master 升级后才可用）

**前置条件**：确保 Agent 已开启 OTA：

```bash
# 在 Agent 上检查
grep "^ENABLE_OTA=" /opt/ip_sentinel/config.conf
# 应为: ENABLE_OTA="true"
```

**操作步骤：**

```
① 先升级 1 个 Agent 做金丝雀
    TG → /start → 全球战区雷达 → 选节点 → OTA 静默升级
    等待节点主动发回 #REGISTER# 确认

② 确认金丝雀正常后，全量升级
    TG → /start → ☢️ 全舰队 OTA 热重载
```

### 4.3 升级后验证

```bash
# 确认版本
grep "^AGENT_VERSION=" /opt/ip_sentinel/config.conf
# 预期: AGENT_VERSION="4.3.2"

# 确认 HMAC_SECRET 已生成
grep "^HMAC_SECRET=" /opt/ip_sentinel/config.conf | cut -d'"' -f2 | wc -c
# 预期: 65（含引号，64 字符 hex）

# 确认旧版备份已清理（升级成功时）
ls -la /opt/ip_sentinel/core.bak 2>/dev/null || echo "✅ 备份已清理或从未创建"

# 查看升级日志
cat /opt/ip_sentinel/logs/ota_upgrade.log 2>/dev/null

# 从 Master 检查 Agent 版本
# 在 TG 发送 /nodes 查看各节点 agent_version
```

---

## 5. 升级后全面验证

### 5.1 TG 功能测试

| 测试项 | 操作 | 预期 |
|--------|------|------|
| Master 面板 | 发送 `/start` | 显示 `v4.3.1` 及菜单 |
| Agent 状态 | `/nodes` 或查看战区雷达 | 5 个 Agent 在线 |
| 全舰队养护 | `run:@all` | 所有 Agent 返回状态 |
| 单节点养护 | 选一个节点 → run | 该节点返回状态 |
| Google 模块 | 选节点 → toggle google:true | Master 返回确认 |

### 5.2 安全防护验证

```bash
# SSRF 防护（Master 端）
curl -s "https://<MASTER_IP>:<PORT>/trigger_ota?t=$(date +%s)&sign=FAKE" | grep -q "401\|403" && echo "✅ HMAC 鉴权生效"

# os.system 无残留（Agent 端）
grep -c "subprocess" /opt/ip_sentinel/core/agent_daemon.sh && echo "✅ subprocess 已使用"
grep -n "os\.system" /opt/ip_sentinel/core/agent_daemon.sh || echo "✅ 无 os.system 残留"

# 证书验证（Master -> Agent 通信使用 pinnedpubkey）
grep -n "pinnedpubkey" /opt/ip_sentinel_master/tg_master.sh && echo "✅ 证书固定验证已启用"
```

### 5.3 服务状态

```bash
systemctl status ip-sentinel-master.service 2>/dev/null | head -3
systemctl status ip-sentinel-agent-daemon.service 2>/dev/null | head -3
```

---

## 6. 回滚方案

### 6.1 Agent 自动回退（已内置）

升级时 `core/install.sh` 自动执行：
1. 升级前 `cp -a core core.bak`
2. 新核心启动后 **等待 3 秒**
3. 检测 `agent_daemon.sh` / `webhook.py` 进程是否存活
4. 如果不存活 → 自动从 `core.bak` 回退 → 重启旧版本 → 发送 TG 告警

**告警信息示例：**
```
⚠️ OTA 升级失败，已自动回退到旧版本
📍 节点: node-us-west-001
📌 原因: 新引擎启动超时无响应
```

### 6.2 手动回滚（当自动回退也失败时）

```bash
# 停止服务
systemctl stop ip-sentinel-master.service 2>/dev/null || pkill -f tg_master.sh 2>/dev/null || true
systemctl stop ip-sentinel-agent-daemon.service 2>/dev/null || pkill -f agent_daemon.sh 2>/dev/null || true

# 恢复备份
rm -rf /opt/ip_sentinel_master && cp -ra /opt/ip_sentinel_master.bak.20260729 /opt/ip_sentinel_master
rm -rf /opt/ip_sentinel && cp -ra /opt/ip_sentinel.bak.20260729 /opt/ip_sentinel

# 重启服务
systemctl daemon-reload
systemctl restart ip-sentinel-master.service || nohup bash /opt/ip_sentinel_master/tg_master.sh > /dev/null 2>&1 &
systemctl restart ip-sentinel-agent-daemon.service || nohup bash /opt/ip_sentinel/core/agent_daemon.sh $(grep "^AGENT_PORT=" /opt/ip_sentinel/config.conf | cut -d'"' -f2) > /dev/null 2>&1 &
```

---

## 7. 风险与注意事项

### 7.1 升级顺序严格
```
先 Master → 后 Agent
```
旧 Master 发 HTTP 明文请求，新 Agent 强制 HTTPS+HMAC 验证。如果先升级 Agent，旧 Master 的所有指令会被 TLS 层拒绝。

### 7.2 HMAC 双轨兼容

- 旧 Agent（无 `HMAC_SECRET`）→ 自动使用 `CHAT_ID` 签名 → Master 端双轨兼容
- 新 Agent（有 `HMAC_SECRET`）→ 优先使用独立密钥
- **所有节点升级完成后**，建议检查所有节点均有独立 `HMAC_SECRET`

### 7.3 默认开启 OTA

Master 升级后 `ENABLE_MASTER_OTA=true`，Agent 需要在 `config.conf` 中确认 `ENABLE_OTA=true`。

### 7.4 GitHub Raw 单点依赖

所有安装/OTA 脚本指向：
```
https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened
```
如果该仓库不可达，安装和 OTA 升级将暂停，但已运行的节点不受影响。

---

## 8. 总结——最快升级路径

```
时间线                    操作                         约耗时
───────                  ────                         ─────
T+0min   ① Master SSH 升级                             3-5 秒
T+1min   ② TG /start 确认 Master 版本正常
T+2min   ③ Agent-1 SSH 升级（金丝雀）                  10-20 秒
T+3min   ④ 验证 Agent-1 上线正常
T+5min   ⑤ 剩余 4 台 Agent SSH 升级                    10-20 秒 × 4
                                或
         ⑤' TG 菜单 → 全舰队 OTA 热重载                 全量约 30 秒
T+10min  ⑥ 全面验证：节点列表、养护循环、安全防护
        ────────────────────────────────────────
        总计：约 10 分钟（SSH）或 5 分钟（OTA）
```

---

> **文档版本**: v2.0 | **最后更新**: 2026-07-29 | **适用分支**: hardened (aduhappy/ip-sentinel-fork)
>
> 有问题请提交 Issue 至 [aduhappy/ip-sentinel-fork](https://github.com/aduhappy/ip-sentinel-fork)
