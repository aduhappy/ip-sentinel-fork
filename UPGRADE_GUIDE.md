# IP-Sentinel 部署升级指南 — hardened 安全增强分支

> **本文档面向已部署原版 IP-Sentinel (hotyue/IP-Sentinel) Master/Agent 的用户，指导如何升级到安全加固的 `hardened` 分支 (aduhappy/ip-sentinel-fork)。**

---

## 1. 概述

### 1.1 hardened 分支与原版的关系

| 维度 | 原版 (hotyue/IP-Sentinel `main`) | hardened 分支 (aduhappy/ip-sentinel-fork `hardened`) |
|---|---|---|
| **代码基础** | 上游主线，功能持续迭代 | 基于上游 v4.3.x 的 fork，追加安全补丁 |
| **安全修复** | 无专门安全审计 | 已修复 7 项安全漏洞（含 3 项 P0 高危） |
| **API 兼容** | 基准 | 完全向后兼容，HMAC 双轨密钥确保旧 Agent 可注册 |
| **运维方式** | 仅 SSH 手动升级 | 支持 OTA 远程静默升级（Master 端优先级更高） |
| **安装源** | `raw.githubusercontent.com/hotyue/IP-Sentinel/main` | `raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened` |

### 1.2 已修复的安全问题清单

#### 已完成修复（7 项）

| 编号 | 严重度 | 漏洞类型 | 说明 | 涉及文件 |
|---|---|---|---|---|
| **P0-001** | 严重 | SSRF 服务器端请求伪造 | 原版仅用 Bash 正则过滤内网 IP，可被绕过；改用 `python3 ipaddress` 库全面验证 |
| **P0-002** | 严重 | 命令注入 (`os.system`) | `agent_daemon.sh` 使用 `os.system()` 调用外部命令，参数未转义；改用 `subprocess.Popen` 数组传参 |
| **P0-003** | 严重 | HMAC 密钥复用 CHAT_ID | HMAC 签名密钥直接使用 CHAT_ID（Chat ID 可被 TG Bot 枚举），独立生成 `HMAC_SECRET` |
| **P1-001** | 高危 | toggle 模块注入 | `tg_master.sh` 中 MOD_NAME 无白名单校验，攻击者可注入任意模块名；新增白名单 `google`/`trust`/`ota` |
| **P1-005** | 高危 | Nonce 缓存无上限 | Nonce 使用普通 `set()` 无大小限制，可被耗尽内存；改为 `OrderedDict` + 100000 上限 |
| **P1-006** | 高危 | 线程池无限制 | `socketserver.ThreadingMixIn` 默认无最大线程数；设置 `max_threads = 50` |
| **P1-012** | 高危 | Shell 变量注入 | `CURL_BIND_OPT` 字符串拼接可被注入；改为 Bash 数组 `CURL_BIND_ARGS=()` |

#### 正在进行/未合并（3 项）

| 编号 | 严重度 | 说明 | 状态 |
|---|---|---|---|
| **P1-002** | 高危 | 探针下载无 TLS 证书验证，面临 MITM 篡改风险 | 待合并 |
| **P1-003** | 高危 | 第三方探针脚本 (xykt/IPQuality) 无完整性校验；已有部分实现 | 已提交 PR，待合并 |
| **P1-008** | 高危 | OTA 升级包无签名验证，可被供应链投毒 | 已提交 PR，待合并 |

---

## 2. 升级前的准备

### 2.1 备份步骤

> **务必先备份，再升级！** 即使安装脚本支持平滑升级，备份是最安全的保底手段。

#### Master 备份

```bash
# 备份整个 Master 目录（包含配置、数据库、核心脚本）
sudo cp -ra /opt/ip_sentinel_master /opt/ip_sentinel_master.bak.$(date +%Y%m%d)

# 单独备份关键文件（可选）
sudo cp /opt/ip_sentinel_master/master.conf /opt/ip_sentinel_master/master.conf.bak
sudo cp /opt/ip_sentinel_master/sentinel.db /opt/ip_sentinel_master/sentinel.db.bak

# 备份 systemd 服务
sudo cp /etc/systemd/system/ip-sentinel-master.service /etc/systemd/system/ip-sentinel-master.service.bak 2>/dev/null || true
```

#### Agent 备份

```bash
# 备份整个 Agent 目录
sudo cp -ra /opt/ip_sentinel /opt/ip_sentinel.bak.$(date +%Y%m%d)

# 单独备份关键文件
sudo cp /opt/ip_sentinel/config.conf /opt/ip_sentinel/config.conf.bak

# 备份 systemd 服务
sudo cp /etc/systemd/system/ip-sentinel-agent.service /etc/systemd/system/ip-sentinel-agent.service.bak 2>/dev/null || true
```

### 2.2 需要记录的关键配置信息清单

升级前，请记录以下信息以备验证或回滚：

```bash
# Master 端
[ -f /opt/ip_sentinel_master/master.conf ] && echo "=== Master 关键参数 ===" && \
  grep -E "^(MASTER_VERSION|TG_TOKEN|MASTER_NODE_NAME|HMAC_SECRET|ENABLE_MASTER_OTA)=" /opt/ip_sentinel_master/master.conf

# Agent 端（每台 VPS）
[ -f /opt/ip_sentinel/config.conf ] && echo "=== Agent 关键参数 ===" && \
  grep -E "^(AGENT_VERSION|REGION_CODE|NODE_NAME|NODE_ALIAS|TG_TOKEN|CHAT_ID|HMAC_SECRET|ENABLE_OTA)=" /opt/ip_sentinel/config.conf
```

**建议保存以下内容到本地安全的文件：**

- Master 的 `HMAC_SECRET`（如果已存在）
- Agent 的 `NODE_NAME` / `NODE_ALIAS` 列表
- `TG_TOKEN`（Bot Token）
- `CHAT_ID`（Telegram Chat ID）

### 2.3 版本检查命令

```bash
# 检查当前 Master 版本
grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf 2>/dev/null || echo "未安装 Master"

# 检查当前 Agent 版本
grep "^AGENT_VERSION=" /opt/ip_sentinel/config.conf 2>/dev/null || echo "未安装 Agent"

# 检查 hardened 分支最新版本
curl -sfL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/version.txt

# 检查安装源指向（确认是否已指向 hardened 分支）
grep "REPO_RAW_URL" /opt/ip_sentinel/core/*.sh 2>/dev/null | head -3
grep "REPO_RAW_URL" /opt/ip_sentinel_master/tg_master.sh 2>/dev/null
```

### 2.4 前置条件检查清单

| 检查项 | 命令 | 预期结果 |
|---|---|---|
| Python3 可用 | `command -v python3` | 输出路径（如 `/usr/bin/python3`） |
| openssl 可用 | `command -v openssl` | 输出路径 |
| curl 可用 | `command -v curl` | 输出路径 |
| root 权限 | `whoami` | `root` |
| 网络连通 | `curl -sfL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/version.txt` | 输出版本号 |
| SQLite3 可用 | `command -v sqlite3` | 输出路径（Master 节点必检） |
| 磁盘空间 | `df -h /opt` | 剩余 >= 100MB |

---

## 3. 升级 Master 节点

> 必须先升级 Master，再升级 Agent！因为某些 Agent 新功能依赖 Master 新接口（如 OTA 签名验证）。

### 3.1 SSH 重新安装方式（推荐）

#### 命令

直接在 Master 服务器上以 root 用户执行：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/master/install_master.sh)"
```

#### 安装过程的行为说明

1. **自动检测旧配置** — 如果 `/opt/ip_sentinel_master/master.conf` 已存在，安装脚本会自动识别为「平滑升级模式」并提示确认。
2. **保留数据库** — 默认保留 `sentinel.db` 不删除（SQLite 中的节点数据不会丢失）。如需清空重建请选 `n`。
3. **保留旧配置** — 升级模式下不会重新收集 `TG_TOKEN` 等参数，直接使用已有 `master.conf`。
4. **新增字段自动补全** — 脚本会自动在 `master.conf` 中追加新配置项：
   - `HMAC_SECRET` — 登录时自动生成并写入，**旧配置中的 `CHAT_ID` 仍然生效（双轨兼容）**
   - `IS_OFFICIAL_GATEWAY` — 默认为 `false`
   - `ENABLE_MASTER_OTA` — 默认为 `false`
   - `MASTER_NODE_NAME` — 自动生成节点别名
5. **版本号更新** — `master.conf` 中的 `MASTER_VERSION` 会自动更新为最新版本。
6. **核心脚本覆写** — `tg_master.sh`、`install_master.sh` 等脚本会被覆盖为 hardened 版本。
7. **systemd 服务重载** — 如果使用 systemd，会自动重载并重启服务。

#### 交互流程示例

```
======================================
📊 IP-Sentinel 中枢靶机环境侦测
--------------------------------------
...
======================================

💡 司令部雷达提示：检测到本机已部署过 Master 中枢。
👉 是否按原配置直接进行平滑升级？(y/n, 默认y): y    ← 回车即可
👉 是否保留历史节点数据库 (SQLite)？(y/n, 默认y): y    ← 建议保留
✅ 已激活 [平滑升级模式]，版本已锚定为 v4.3.1...
```

### 3.2 手动替换方式（离线环境备选）

如果 Master 服务器无法直接访问 GitHub（内网/离线环境），可先下载脚本再传输执行。

#### 步骤

在 **可访问 GitHub 的机器** 上下载脚本打包：

```bash
# 创建临时工作目录
mkdir -p /tmp/ip-sentinel-master-upgrade && cd /tmp/ip-sentinel-master-upgrade

# 下载 hardened 分支的 Master 相关文件
BASE_URL="https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened"
curl -sfLO "${BASE_URL}/master/install_master.sh"
curl -sfLO "${BASE_URL}/master/tg_master.sh"
curl -sfLO "${BASE_URL}/master/uninstall_master.sh"
curl -sfLO "${BASE_URL}/install/env_setup.sh"
curl -sfLO "${BASE_URL}/install/master_setup.sh"
curl -sfLO "${BASE_URL}/install/build_master.sh"
curl -sfLO "${BASE_URL}/version.txt"

# 打包传输到目标 Master 服务器
tar czf ip-sentinel-master-upgrade.tar.gz .
# 使用 scp/rsync 等方式传输到 Master 服务器
```

在 **Master 服务器** 上执行手动升级：

```bash
# 1. 停止当前 Master 服务
systemctl stop ip-sentinel-master.service 2>/dev/null || pkill -f tg_master.sh 2>/dev/null || true

# 2. 备份（如尚未备份）
cp -ra /opt/ip_sentinel_master /opt/ip_sentinel_master.bak.$(date +%Y%m%d)

# 3. 解压文件到临时目录并执行安装
cd /tmp/ip-sentinel-master-upgrade
export REPO_RAW_URL="https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened"
export SECURE_TMP="/tmp/ips_master_upgrade"
export TARGET_VERSION=$(grep "^MASTER_VERSION=" version.txt | cut -d'=' -f2)
mkdir -p "$SECURE_TMP"

# 4. 手动执行核心安装逻辑
source install/env_setup.sh
source install/master_setup.sh

# 5. 依次执行安装步骤
do_master_env_precheck
do_fetch_master_version
do_master_handle_menu   # 选择升级模式
do_install_deps
do_master_clean_env
do_master_config        # 升级模式会保留旧配置
do_master_init_db
do_master_deploy_core
do_master_summary

# 清理
rm -rf /tmp/ip-sentinel-master-upgrade "$SECURE_TMP"
```

### 3.3 升级后验证

```bash
# 确认版本已更新
grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf

# 确认 HMAC_SECRET 已生成
grep "^HMAC_SECRET=" /opt/ip_sentinel_master/master.conf | wc -l
# 预期输出: 1

# 确认 SSRF 防护已启用（查看 tg_master.sh 中的 SSRF 拦截代码）
grep -n "ipaddress\|SSRF\|ssrf" /opt/ip_sentinel_master/tg_master.sh | head -5

# 确认服务正在运行
systemctl status ip-sentinel-master.service 2>/dev/null || pgrep -fl tg_master.sh
```

---

## 4. 升级 Agent 节点

### 4.1 SSH 逐个升级方式

> 适用于节点数较少（< 50 台）或无法使用 OTA 的场景。

#### 命令

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/install.sh)"
```

#### 安装引擎会自动保留原有配置

1. 安装脚本自动检测 `/opt/ip_sentinel/config.conf` 是否存在。
2. 如存在，提示是否「按原配置直接进行平滑升级」，选择 `y`。
3. 升级模式会 **完全跳过** `TG_TOKEN`、`CHAT_ID`、`REGION_CODE` 等配置收集。
4. 升级模式 **不会覆盖** `config.conf`，仅在旧配置基础上添加新字段：
   - `HMAC_SECRET` — 安装时自动生成（Agent 端也使用独立密钥）
5. 所有旧字段（`TG_TOKEN`、`CHAT_ID`、`NODE_NAME` 等）**保持不变**。
6. 升级完成后自动重启 Agent 守护进程。

#### 交互示例

```
请选择操作:
  1) 🚀 部署/平滑升级 Agent 边缘节点
  2) 🗑️ 一键卸载 Agent

💡 检测到本机已部署过 IP-Sentinel 节点。
👉 是否按原配置直接进行平滑升级？(y/n, 默认y): y    ← 回车
✅ 已激活 [平滑升级模式]，即将跳过基础配置，直接更新核心装甲...
```

### 4.2 OTA 远程静默升级（私有中枢批量）

> 适用于大规模集群（50+ 节点），无需逐台 SSH 登录。

#### 前置条件

- [ ] Master **必须先升级** 到 hardened 分支（否则 Agent 虽可升级但 OTA 功能不完整）
- [ ] Master 配置中 `ENABLE_MASTER_OTA="true"`（安装时已选择开启 OTA）
- [ ] Agent 配置中 `ENABLE_OTA="true"`（安装时已选择开启 OTA）
- [ ] Agent 的 REPO_RAW_URL 已在 `agent_daemon.sh` 中指向 hardened 分支（升级后会更新）

#### Telegram Bot 操作步骤

1. 打开 Telegram 中与 Master Bot 的对话。
2. 发送 `/nodes` 查看所有已注册节点列表。
3. 找到需要升级的节点，记下其节点名称（如 `node-us-west-001-A1B2`）。
4. **单节点 OTA 升级**：发送命令 `ota <节点名称>`，例如：
   ```
   ota node-us-west-001-A1B2
   ```
5. **全舰队 OTA 升级**：在 Bot 菜单中选择「全舰队 OTA 升级」按钮，或在任意聊天中发送 `fleet_ota` 命令。
6. 等待节点逐一汇报升级结果，升级成功时节点会发送新的注册确认消息。

**OTA 升级流程内部机制：**

```
Master 收到 ota 指令
  → 从 REPO_RAW_URL 拉取 install.sh 并计算 SHA256 哈希
  → 通过 HMAC 签名通道向 Agent 发送 /trigger_ota 指令
  → Agent 验证签名后执行 install.sh（静默模式，SILENT_AGENT_OTA=true）
  → 安装引擎自动检测升级模式，保留 config.conf
  → 升级完成后 Agent 自动重启守护进程
  → Agent 向 Master 发送新的注册确认（#REGISTER#）
```

#### 全舰队升级注意事项

- 全舰队 OTA 会逐个节点下发（间隔 0.3 秒），避免「惊群效应」。
- OTA 升级过程中请勿在 Master 上执行其他写操作（如卸载节点）。
- 建议先对 1-2 个节点进行灰度验证，确认无误后再执行全舰队升级。

---

## 5. 升级后验证

### 5.1 版本确认

```bash
# Master 版本
echo -n "Master: "; grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf 2>/dev/null || echo "NOT_INSTALLED"

# Agent 版本
echo -n "Agent: "; grep "^AGENT_VERSION=" /opt/ip_sentinel/config.conf 2>/dev/null || echo "NOT_INSTALLED"
```

预期输出：

```
Master: MASTER_VERSION="4.3.1"
Agent:  AGENT_VERSION="4.3.2"
```

### 5.2 HMAC_SECRET 确认

```bash
# Master 端确认存在独立密钥
echo "Master HMAC_SECRET:"
grep "^HMAC_SECRET=" /opt/ip_sentinel_master/master.conf | head -1

# Agent 端确认存在独立密钥
echo "Agent HMAC_SECRET:"
grep "^HMAC_SECRET=" /opt/ip_sentinel/config.conf | head -1

# 确认密钥不等于 CHAT_ID（若旧版本升级后未重新安装则可能没有 HMAC_SECRET）
if grep -q "^HMAC_SECRET=" /opt/ip_sentinel/config.conf 2>/dev/null; then
    HMAC_SECRET=$(grep "^HMAC_SECRET=" /opt/ip_sentinel/config.conf | cut -d'"' -f2)
    CHAT_ID=$(grep "^CHAT_ID=" /opt/ip_sentinel/config.conf | cut -d'"' -f2)
    if [ "$HMAC_SECRET" != "$CHAT_ID" ]; then
        echo "✅ HMAC_SECRET 与 CHAT_ID 不同，密钥隔离生效"
    else
        echo "⚠️ HMAC_SECRET 与 CHAT_ID 相同，请考虑重新安装以生成独立密钥"
    fi
fi
```

### 5.3 SSRF 防护确认

```bash
# Master 端确认使用了 python3 ipaddress 库
grep -c "ipaddress" /opt/ip_sentinel_master/tg_master.sh 2>/dev/null && echo "✅ SSRF 防护已启用 (Python ipaddress)" || echo "⚠️ SSRF 防护未检测到"

# Agent 端确认不再使用 curl ipinfo.io 代理 SSRF（仅用于 ISP 查询，属于正常业务）
grep -n "internal\|private\|loopback\|SSRF" /opt/ip_sentinel_master/tg_master.sh 2>/dev/null | head -3
```

### 5.4 os.system 无残留确认

```bash
# Agent 端确认 subprocess 已替代 os.system
grep -c "subprocess" /opt/ip_sentinel/core/agent_daemon.sh 2>/dev/null && echo "✅ 已使用 subprocess 安全调用" || echo "⚠️ 未使用 subprocess，存在命令注入风险"

# 确认无 os.system 残留
grep -n "os\.system" /opt/ip_sentinel/core/agent_daemon.sh 2>/dev/null && echo "⚠️ 存在 os.system 残留！" || echo "✅ 无 os.system 残留"
```

### 5.5 服务状态确认

```bash
# Master 服务
systemctl status ip-sentinel-master.service 2>/dev/null | head -5 || echo "⚠️ 未使用 systemd (看门狗模式)"

# Agent 服务
systemctl status ip-sentinel-agent.service 2>/dev/null | head -5 || echo "⚠️ 未使用 systemd (看门狗模式)"

# 备用：检查进程存活
echo "--- 进程检查 ---"
pgrep -fl "tg_master" && echo "✅ Master 进程运行中" || echo "⚠️ Master 进程未运行"
pgrep -fl "agent_daemon" && echo "✅ Agent 进程运行中" || echo "⚠️ Agent 进程未运行"
```

### 5.6 功能测试

```bash
# 验证 Bot 在线（前提：TG_TOKEN 配置正确）
# 在 Telegram 中向你的 Bot 发送 /start
# 预期：Bot 应正常回复菜单或状态信息

# 验证 Agent 养护循环
# Agent 每 20 分钟自动执行一次养护循环，可查看日志确认
sudo tail -20 /opt/ip_sentinel/logs/sentinel.log 2>/dev/null

# 验证 Master 正常监听
# 查看 Master 日志中的更新轮询
sudo journalctl -u ip-sentinel-master.service --no-pager -n 20 2>/dev/null || \
  sudo tail -20 /opt/ip_sentinel_master/logs/*.log 2>/dev/null || \
  echo "请手动检查 Master 运行状态"
```

---

## 6. 回滚方案

> 如果升级后出现问题（如 Master 无法启动、Agent 无法注册、功能异常等），可按以下步骤回滚到原版。

### 6.1 停止服务

```bash
# 停止 Master
systemctl stop ip-sentinel-master.service 2>/dev/null || pkill -f tg_master.sh 2>/dev/null || true

# 停止 Agent（需要逐台执行）
systemctl stop ip-sentinel-agent.service 2>/dev/null || pkill -f agent_daemon.sh 2>/dev/null || true
```

### 6.2 恢复备份目录

```bash
# 恢复 Master
rm -rf /opt/ip_sentinel_master
cp -ra /opt/ip_sentinel_master.bak.$(date +%Y%m%d) /opt/ip_sentinel_master

# 恢复 Agent（逐台执行）
rm -rf /opt/ip_sentinel
cp -ra /opt/ip_sentinel.bak.$(date +%Y%m%d) /opt/ip_sentinel
```

### 6.3 重启原版服务

```bash
# Master
systemctl daemon-reload 2>/dev/null
systemctl restart ip-sentinel-master.service 2>/dev/null || {
  # 看门狗模式：直接启动
  nohup bash /opt/ip_sentinel_master/tg_master.sh > /dev/null 2>&1 &
}

# Agent（逐台执行）
systemctl restart ip-sentinel-agent.service 2>/dev/null || {
  nohup bash /opt/ip_sentinel/core/agent_daemon.sh $(grep "^AGENT_PORT=" /opt/ip_sentinel/config.conf | cut -d'"' -f2) > /dev/null 2>&1 &
}
```

### 6.4 恢复到上游的 REPO_RAW_URL

回滚后，如果希望恢复到原版仓库（而非 hardened），需修改所有脚本中的 `REPO_RAW_URL`：

```bash
# 查看当前 REPO_RAW_URL 分布
grep -rn "REPO_RAW_URL" /opt/ip_sentinel/core/ /opt/ip_sentinel_master/ 2>/dev/null

# 批量替换为原版地址
ORIG_URL="https://raw.githubusercontent.com/hotyue/IP-Sentinel/main"
HARDENED_URL="https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened"

# Master 端
sed -i "s|$HARDENED_URL|$ORIG_URL|g" /opt/ip_sentinel_master/tg_master.sh

# Agent 端
sed -i "s|$HARDENED_URL|$ORIG_URL|g" /opt/ip_sentinel/core/agent_daemon.sh
sed -i "s|$HARDENED_URL|$ORIG_URL|g" /opt/ip_sentinel/core/updater.sh
sed -i "s|$HARDENED_URL|$ORIG_URL|g" /opt/ip_sentinel/core/tg_report.sh
sed -i "s|$HARDENED_URL|$ORIG_URL|g" /opt/ip_sentinel/core/mod_quality.sh
sed -i "s|$HARDENED_URL|$ORIG_URL|g" /opt/ip_sentinel/core/mod_trust.sh

# 确认已全部替换
grep -rn "$HARDENED_URL" /opt/ip_sentinel/core/ /opt/ip_sentinel_master/ 2>/dev/null || echo "✅ 所有 REPO_RAW_URL 已恢复为原版"
```

---

## 7. 升级风险与注意事项

### 7.1 HMAC_SECRET 双轨兼容机制说明

Hardened 分支引入了独立于 `CHAT_ID` 的 `HMAC_SECRET` 密钥体系。为确保 **平滑升级不中断**，采用了双轨兼容设计：

- **新安装/升级的节点**：`config.conf` / `master.conf` 中包含 `HMAC_SECRET`，Agent 和 Master 均优先使用 `HMAC_SECRET` 进行 HMAC-SHA256 签名。
- **老版本节点（未升级）**：`config.conf` 中没有 `HMAC_SECRET` 字段，Agent 自动回退使用 `CHAT_ID` 作为 HMAC 密钥。
- **Master 兼容**：Master 端也采用相同双轨逻辑，与未升级的 Agent 通讯时自动使用 `CHAT_ID`。

**这意味着**:
- Master/Agent 可以混合升级，不会出现通讯中断。
- 建议在 **所有节点升级完成后**，通过重新安装（选择「保留原配置」）为每个节点生成独立的 `HMAC_SECRET`。
- 如果你手动修改过 `HMAC_SECRET`，请确保 Master 和 Agent 使用相同的密钥——这需要在 Master 和 Agent 的配置文件中同步设置。

### 7.2 REPO_RAW_URL 指向 fork 仓库的单点依赖风险

Hardened 分支的所有安装脚本、更新脚本、OTA 拉取均指向：

```
https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened
```

如果该仓库或分支被删除、锁定、或 GitHub Raw CDN 不可达，**将导致以下影响**：

| 受影响的操作 | 严重程度 | 说明 |
|---|---|---|
| 新安装 | 阻断 | `install.sh` / `install_master.sh` 无法下载 |
| OTA 升级 | 阻断 | 升级脚本和核心文件无法拉取 |
| 每日词库更新 | 阻断 | `updater.sh` 无法同步热搜词和探针 |
| 已运行的 Agent/Master | 低 | 已有进程不受影响，可继续运行 |
| SSRF/Toggle/其他安全防护 | 低 | 已部署的防护代码不受影响 |

**缓解措施**：

1. 定期同步 hardened 分支到自有仓库（见 8.1 节）。
2. 自建 GitHub Raw Mirror（见 8.2 节）。
3. 保留一份完整备份，在极端情况下手动恢复。

### 7.3 上游更新同步策略

Hardened 分支基于上游的 v4.3.x 版本。上游 `hotyue/IP-Sentinel` 会持续迭代新功能，同步策略如下：

```bash
# 将上游 main 分支合并到 hardened
git remote add upstream https://github.com/hotyue/IP-Sentinel.git
git fetch upstream main
git checkout hardened
git merge upstream/main --no-edit
```

**注意**：
- 合并后需重新验证安全补丁是否被覆盖（尤其是 `master/tg_master.sh` 和 `core/agent_daemon.sh`）。
- 合并后务必更新 `REPO_RAW_URL` 指向（如果上游修改了相关路径）。
- 合并后建议的测试：在至少 1 台 Agent 上运行升级并验证功能。

### 7.4 Python3 可用性依赖

- `agent_daemon.sh` 作为 Python3 HTTPS 守护进程运行，**必须确保 `python3` 可用**。
- SSRF 防护同样依赖 `python3`（`ipaddress` 标准库模块无需额外安装）。
- 绝大多数 Linux 发行版默认包含 `python3`，如果缺少请提前安装。

```bash
# 安装 python3（如缺失）
# Debian/Ubuntu
apt-get install -y python3

# CentOS/RHEL
yum install -y python3

# Alpine
apk add python3
```

### 7.5 建议的灰度升级策略

为避免大规模故障，建议按以下步骤渐进式升级：

```
验证 → 灰度 → 全量 → 确认
```

| 阶段 | 操作 | 说明 | 回滚时间 |
|---|---|---|---|
| **验证** | 在 1 台新 VPS 上全新安装 hardened 分支 | 确认安装、注册、养护循环正常运行 | 随时 |
| **灰度 Master** | 升级 1 台 Master（如有多台） | 确认 Bot 响应、OTA 指令、节点列表正常 | 5 分钟 |
| **灰度 Agent** | 选择 2-3 台低价值 Agent 升级 | 确认升级后养护、上报、注册正常 | 10 分钟 |
| **全量 Agent** | 逐批升级剩余 Agent（建议每批 20 台） | 使用 OTA 或 SSH 批量执行 | 30 分钟 |
| **全量确认** | 全面验证所有节点状态 | 确认版本统一、HMAC_SECRET 生效、无告警 | — |

---

## 8. 升级后的后续维护

### 8.1 定期同步上游 main 分支到 hardened

建议每隔 2-4 周同步一次上游更新：

```bash
# 克隆 hardened 分支到本地（如尚未克隆）
git clone -b hardened https://github.com/aduhappy/ip-sentinel-fork.git
cd ip-sentinel-fork

# 添加上游仓库
git remote add upstream https://github.com/hotyue/IP-Sentinel.git

# 同步上游
git fetch upstream main
git checkout hardened
git merge upstream/main --no-edit

# 处理冲突（重点检查以下文件）
# - master/tg_master.sh
# - core/agent_daemon.sh
# - core/tg_report.sh
# - core/updater.sh
# - core/mod_quality.sh
# - install/*.sh

# 确认安全补丁未被覆盖
grep -n "ipaddress" master/tg_master.sh       # SSRF 防护应存在
grep -n "subprocess" core/agent_daemon.sh     # os.system 应已替换
grep -n "HMAC_SECRET" core/agent_daemon.sh    # 独立密钥应存在

# 推送回 hardened 分支
git push origin hardened
```

### 8.2 自建 Mirror 的建议

为避免单点依赖风险，建议自建 hardened 分支的镜像仓库：

1. **GitHub Fork**：Fork `aduhappy/ip-sentinel-fork` 到自有组织或个人账号，将 `REPO_RAW_URL` 指向自有 fork。
2. **Gitee/自建 Git 服务**：定期从 GitHub 同步，并修改 `REPO_RAW_URL` 指向国内镜像源。
3. **私有 Raw CDN**：使用 Cloudflare Workers、GitHub Proxy 等代理服务，减少直接依赖 GitHub Raw CDN。

### 8.3 持续监控 hardened 分支的更新

- Watch 仓库：在 GitHub 上 Watch `aduhappy/ip-sentinel-fork` 仓库的 Release 和 Commit 通知。
- 定期检查新提交：
  ```bash
  # 查看 hardened 分支最新的 5 个 commit
  curl -sfL "https://api.github.com/repos/aduhappy/ip-sentinel-fork/commits/hardened" | \
    python3 -c "import sys,json; [print(c['sha'][:8], c['commit']['message'].split('\n')[0]) for c in json.load(sys.stdin)[:5]]"
  ```
- 加入官方 Telegram 频道 `@IP_Sentinel_Matrix` 获取上游更新通知。
- 关注 `CHANGELOG.md` 了解版本变动。
- 关注进行中的补丁（P1-002、P1-003、P1-008）的合并状态。

---

> **文档版本**: v1.0 | **最后更新**: 2026-07-29 | **适用分支**: hardened (aduhappy/ip-sentinel-fork)
>
> 如有问题，请提交 Issue 至 [aduhappy/ip-sentinel-fork](https://github.com/aduhappy/ip-sentinel-fork) 仓库。
