#!/bin/bash

# ==========================================================
# 脚本名称: agent_daemon.sh
# 核心功能: TLS 隧道构建、HMAC 动态鉴权、防重放攻击、模块级零信任路由
# ==========================================================

INSTALL_DIR="/opt/ip_sentinel"
CONFIG_FILE="${INSTALL_DIR}/config.conf"
IP_CACHE="${INSTALL_DIR}/core/.last_ip"

[ ! -f "$CONFIG_FILE" ] && exit 1
source "$CONFIG_FILE"

# [战术核心] 若未配置司令部凭证，则判定为单机运行模式，主动进入休眠
[ -z "$TG_TOKEN" ] || [ -z "$CHAT_ID" ] && exit 0

AGENT_PORT=${AGENT_PORT:-9527}

# ----------------------------------------------------------
# [身份锚定] 载入不可变主键与展示别名 (双轨身份映射)
# ----------------------------------------------------------
if [ -z "$NODE_NAME" ]; then
    IP_HASH=$(echo "${PUBLIC_IP:-127.0.0.1}" | md5sum | cut -c 1-4 | tr 'a-z' 'A-Z')
    NODE_NAME="$(hostname | tr -cd 'a-zA-Z0-9' | cut -c 1-10)-${IP_HASH}"
fi
NODE_ALIAS="${NODE_ALIAS:-$NODE_NAME}"

# ----------------------------------------------------------
# [网络侦测] 实时公网 IP 嗅探与静默状态更新
# ----------------------------------------------------------
RAW_IP=$(curl -${IP_PREF:-4} -s -m 5 api.ip.sb/ip | tr -d '[:space:]')

# [防线/容灾] 为 IPv6 自动装载方括号护甲；API 失效时退回静态配置锚点
if [ -n "$RAW_IP" ]; then
    if [[ "$RAW_IP" == *":"* ]] && [[ "$RAW_IP" != *"["* ]]; then
        AGENT_IP="[${RAW_IP}]"
    else
        AGENT_IP="$RAW_IP"
    fi
else
    AGENT_IP="${PUBLIC_IP:-${BIND_IP:-Unknown}}"
fi

if [ -n "$AGENT_IP" ]; then
    LAST_IP=""
    [ -f "$IP_CACHE" ] && LAST_IP=$(cat "$IP_CACHE" | tr -d '[:space:]')

    if [ "$AGENT_IP" != "$LAST_IP" ]; then
        # [底层交互] 仅执行本地缓存重写，切除高频发信逻辑，保持静默侦听
        echo "$AGENT_IP" > "$IP_CACHE"
        echo "ℹ️ [Agent] 发现本地 IP 变动，已静默更新缓存: $AGENT_IP"
    else
        echo "ℹ️ [Agent] IP 未变动 ($AGENT_IP)，继续后台静默监听。"
    fi
fi

# [v4.2.2 终极架构] 彻底剥离 Bash 对底层网络栈的干预，将控制权全权移交 Python 全域引擎
echo "🌐 [Agent] 底层网络栈已解锁，准备切入全域双栈监听模式 (Dual-Stack Universal Bind)"

# ==========================================================
# [加密通信] 强制构建自签名 TLS 装甲，屏蔽中间人嗅探
# ==========================================================
CERT_FILE="${INSTALL_DIR}/core/cert.pem"
KEY_FILE="${INSTALL_DIR}/core/key.pem"

# [v4.2.2 热修复] 检查证书是否过于陈旧，若是则强制销毁重铸 (保障平滑升级的 TLS 健康)
if [ -f "$CERT_FILE" ]; then
    CERT_DATE=$(openssl x509 -noout -startdate -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
    if [[ -n "$CERT_DATE" ]]; then
        CERT_EPOCH=$(date -d "$CERT_DATE" +%s 2>/dev/null || echo 0)
        V422_EPOCH=$(date -d "2026-05-31" +%s 2>/dev/null || echo 1780185600)
        if [ "$CERT_EPOCH" -lt "$V422_EPOCH" ]; then
            echo "🧹 [Agent] 侦测到旧版 (v4.2.2 前) 遗留 TLS 装甲，正在执行强制物理销毁..."
            rm -f "$CERT_FILE" "$KEY_FILE"
        fi
    fi
fi
CERT_FILE="${INSTALL_DIR}/core/cert.pem"
KEY_FILE="${INSTALL_DIR}/core/key.pem"
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "🔐 [Agent] 正在生成本地自签名 TLS 加密证书 (2048位 RSA)..."
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=US/O=IP-Sentinel/CN=Agent-Sec" >/dev/null 2>&1 || true
fi

# ==========================================================
# [引擎核心] Python3 高并发 Webhook 侦听与路由枢纽
# ==========================================================
cat > "${INSTALL_DIR}/core/webhook.py" << 'EOF'
import http.server
import socketserver
import subprocess
import sys
import os
import html
import re
import urllib.parse
import urllib.request
import hmac
import hashlib
import time
import threading
from collections import OrderedDict

PORT = int(sys.argv[1])

# ----------------------------------------------------------
# [防御矩阵] Nonce 缓存池防重放攻击 (Replay Attack)
# ----------------------------------------------------------
MAX_NONCE_CACHE = 100000
USED_SIGNS = OrderedDict()
NONCE_LOCK = threading.Lock()

def clean_used_signs():
    now = time.time()
    # [安全策略] 滑动窗口清理过期条目，性能优化为从头检查（OrderedDict FIFO 特性）
    # 调用方必须持有 NONCE_LOCK
    while USED_SIGNS:
        s, t = next(iter(USED_SIGNS.items()))
        if now - t > 65:
            del USED_SIGNS[s]
        else:
            break

# [权限鉴权] 提取 HMAC_SECRET 作为 PSK 预共享密钥（双轨兼容：无 HMAC_SECRET 时回退至 CHAT_ID）
AUTH_TOKEN = ""
CHAT_ID = ""
if os.path.exists('/opt/ip_sentinel/config.conf'):
    with open('/opt/ip_sentinel/config.conf', 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('HMAC_SECRET='):
                AUTH_TOKEN = line.split('=', 1)[1].strip('"\'')
                break
    # 向后兼容：无 HMAC_SECRET 时使用 CHAT_ID
    if not AUTH_TOKEN:
        with open('/opt/ip_sentinel/config.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('CHAT_ID='):
                    AUTH_TOKEN = line.split('=', 1)[1].strip('"\'')
                    break
    # [HMAC 密钥同步] 加载 CHAT_ID 供 /setkey 引导验签使用（密钥轮换时刻双方共享秘密）
    if not CHAT_ID:
        with open('/opt/ip_sentinel/config.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('CHAT_ID='):
                    CHAT_ID = line.split('=', 1)[1].strip('"\'')
                    break

class AgentHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global AUTH_TOKEN
        # [权限校验] 路径解析与 HMAC-SHA256 动态签名核验
        parsed = urllib.parse.urlparse(self.path)
        req_path = parsed.path
        
        query = urllib.parse.parse_qs(parsed.query)
        
        if AUTH_TOKEN:
            req_t = query.get('t', [''])[0]
            req_sign = query.get('sign', [''])[0]
            
            if not req_t or not req_sign:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"401 Unauthorized: Missing Signature\n")
                return
                
            try:
                current_time = int(time.time())
                # [防重放 1] 校验时间戳防偏离 (±60秒窗口，免疫隔夜抓包重放)
                if abs(current_time - int(req_t)) > 60:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"401 Unauthorized: Request Expired\n")
                    return
            except ValueError:
                self.send_response(401)
                self.end_headers()
                return
            
            # [防重放 2] Nonce 精确核对 (拦截 60 秒内的 MITM 并发重放洗劫)
            with NONCE_LOCK:
                clean_used_signs()
                if req_sign in USED_SIGNS:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"401 Unauthorized: Replay Attack Detected\n")
                    return
                
                # [身份核验] 数据完整性校验，使用 compare_digest 免疫时序探测攻击
                msg = f"{req_path}:{req_t}".encode('utf-8')
                expected_sign = hmac.new(AUTH_TOKEN.encode('utf-8'), msg, hashlib.sha256).hexdigest()
                sign_ok = hmac.compare_digest(expected_sign, req_sign)
                
                # [HMAC 密钥同步] 引导式验签（仅 /setkey）：已持有旧随机密钥的 Agent，在密钥轮换时刻
                # 额外接受以 CHAT_ID 签名的 setkey 指令（注册时双方唯一已知共享秘密），确保密钥可平滑下发。
                # [安全] 引导仅当 AUTH_TOKEN 仍等于 CHAT_ID（密钥尚未轮换的初始状态）时有效；
                # 一旦 setkey 成功轮换，AUTH_TOKEN != CHAT_ID 后引导立即关闭，
                # 堵死"CHAT_ID 泄露 → 离线伪造 /setkey 轮换密钥"的节点失联攻击。
                if not sign_ok and req_path == '/setkey' and AUTH_TOKEN == CHAT_ID:
                    try:
                        bootstrap_expected = hmac.new(str(CHAT_ID).encode('utf-8'), msg, hashlib.sha256).hexdigest()
                        sign_ok = hmac.compare_digest(bootstrap_expected, req_sign)
                    except Exception:
                        pass
                
                if not sign_ok:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"401 Unauthorized: Signature Mismatch\n")
                    return
                
                # [Nonce 缓存大小保护] 防止内存耗尽攻击
                if len(USED_SIGNS) >= MAX_NONCE_CACHE:
                    self.send_response(429)
                    self.end_headers()
                    self.wfile.write(b"429 Too Many Requests: Nonce cache full\n")
                    return
                
                # 鉴权通过，登记 Nonce 载荷
                USED_SIGNS[req_sign] = current_time

        # ==========================================================
        # [指令分发] 模块级业务路由矩阵 (精确匹配策略)
        # ==========================================================
        
        # 路由 0: 全局统筹调度
        if req_path == '/trigger_run':
            if os.path.exists('/opt/ip_sentinel/core/runner.sh'):
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Action Accepted: runner\n")
                subprocess.Popen(["nohup", "bash", "/opt/ip_sentinel/core/runner.sh"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            else:
                self.send_response(404)
                self.end_headers()
                
        # 路由 1: Google 区域纠偏探测
        elif req_path == '/trigger_google':
            if os.path.exists('/opt/ip_sentinel/core/mod_google.sh'):
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Action Accepted: mod_google\n")
                subprocess.Popen(["nohup", "bash", "/opt/ip_sentinel/core/mod_google.sh"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            else:
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"403 Forbidden: Google Module Disabled\n")

        # 路由 2: IP 信用数据清洗
        elif req_path == '/trigger_trust':
            if os.path.exists('/opt/ip_sentinel/core/mod_trust.sh'):
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Action Accepted: mod_trust\n")
                subprocess.Popen(["nohup", "bash", "/opt/ip_sentinel/core/mod_trust.sh"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            else:
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"403 Forbidden: Trust Module Disabled\n")

        # 路由 3: 触发异步战报生成
        elif req_path == '/trigger_report':
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Action Accepted: tg_report\n")
            subprocess.Popen(["nohup", "bash", "/opt/ip_sentinel/core/tg_report.sh"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

        # 路由 4: 获取并回传实时日志切片
        elif req_path == '/trigger_log':
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Action Accepted: fetch_log\n")
                        
            try:
                config = {}
                if os.path.exists('/opt/ip_sentinel/config.conf'):
                    with open('/opt/ip_sentinel/config.conf', 'r') as f:
                        for line in f:
                            line = line.strip()
                            if '=' in line and not line.startswith('#'):
                                key, val = line.split('=', 1)
                                config[key] = val.strip('"\'')
                
                log_data = "日志文件不存在或为空"
                log_path = '/opt/ip_sentinel/logs/sentinel.log'
                if os.path.exists(log_path):
                    with open(log_path, 'r', errors='ignore') as f:
                        lines = f.readlines()
                        if lines:
                            log_data = html.escape("".join(lines[-15:]))
                
                # 动态提取终端状态以构建回传信息
                local_ver = config.get('AGENT_VERSION', '未知')
                node_alias = config.get('NODE_ALIAS', config.get('NODE_NAME', 'Unknown-Node'))
                
                text_msg = f"📄 <b>[{node_alias}] 实时日志 (v{local_ver}):</b>\n<pre><code>{log_data}</code></pre>"
                
                # [交互反馈] 构建内联 JSON Payload 回调指令
                import json
                node_name_cb = config.get('NODE_NAME', 'Unknown')
                payload = {
                    'chat_id': config.get('CHAT_ID', ''),
                    'text': text_msg,
                    'parse_mode': 'HTML',
                    'reply_markup': {
                        'inline_keyboard': [[{'text': '⚙️ 调出该节点控制台', 'callback_data': f'manage:{node_name_cb}'}]]
                    }
                }
                data = json.dumps(payload).encode('utf-8')
                
                req = urllib.request.Request(
                    config.get('TG_API_URL', ''), 
                    data=data,
                    headers={
                        'User-Agent': f'IP-Sentinel-Agent/{local_ver}',
                        'Content-Type': 'application/json'
                    }
                )
                urllib.request.urlopen(req, timeout=10)
                
            except Exception as e:
                print(f"Log transmission failed: {e}")

        # 路由 5: 深海声呐模块触发
        elif req_path == '/trigger_quality':
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Action Accepted: trigger_quality\n")
            
            if os.path.exists('/opt/ip_sentinel/core/mod_quality.sh'):
                subprocess.Popen(["nohup", "bash", "/opt/ip_sentinel/core/mod_quality.sh"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

        # 路由 6: 节点展示别名热修改 (全量 WAF 防护)
        elif req_path == '/trigger_rename':
            b64_alias = query.get('b64', [''])[0]
            if not b64_alias:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"400 Bad Request: Alias is empty\n")
                return
                
            import re
            import base64
            try:
                # [防线/容灾] 还原安全 Base64 编码，屏蔽乱码级注入风险
                pad = len(b64_alias) % 4
                if pad > 0:
                    b64_alias += '=' * (4 - pad)
                b64_alias = b64_alias.replace('-', '+').replace('_', '/')
                raw_alias = base64.b64decode(b64_alias).decode('utf-8', errors='ignore')
                
                # 强格式清洗：剔除潜在非法字符，保护 TG 面板不被恶意解析撑爆
                decoded_alias = raw_alias.replace('_', '-')
                safe_alias = re.sub(r'[^a-zA-Z0-9\-\u4e00-\u9fa5]', '', decoded_alias)[:20]
                
                if safe_alias:
                    # [底层交互] 利用 fcntl 独占锁执行安全写操作，防止并发数据被截断
                    config_path = '/opt/ip_sentinel/config.conf'
                    import fcntl
                    with open(config_path, 'r+', encoding='utf-8', errors='ignore') as f:
                        fcntl.flock(f, fcntl.LOCK_EX)
                        lines = f.readlines()
                        
                        alias_found = False
                        for i, line in enumerate(lines):
                            if line.startswith('NODE_ALIAS='):
                                lines[i] = f'NODE_ALIAS="{safe_alias}"\n'
                                alias_found = True
                                break
                                
                        if not alias_found:
                            lines.append(f'NODE_ALIAS="{safe_alias}"\n')
                            
                        f.seek(0)
                        f.writelines(lines)
                        f.truncate()
                        fcntl.flock(f, fcntl.LOCK_UN)
                        
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Action Accepted: trigger_rename\n")
                    return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Internal Error: {str(e)}\n".encode('utf-8'))
                return
            
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"400 Bad Request: Invalid Characters\n")

        # 路由 7: 证书指纹查询 (TLS Pinning)
        elif req_path == '/cert_fp':
            try:
                cert_path = '/opt/ip_sentinel/core/cert.pem'
                if os.path.exists(cert_path):
                    # [P1-002] 返回公钥(DER)的 SHA256 base64，供 curl --pinnedpubkey "sha256//<b64>" 使用
                    # 全链路 bytes 管线：PEM(ascii) -> DER(binary) -> hash(binary) -> base64(ascii)
                    result = subprocess.run(
                        ['openssl', 'x509', '-pubkey', '-in', cert_path, '-noout'],
                        capture_output=True)
                    if result.returncode != 0:
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b"500 Cannot read certificate\n")
                        return
                    result2 = subprocess.run(
                        ['openssl', 'pkey', '-pubin', '-outform', 'DER'],
                        input=result.stdout, capture_output=True)
                    if result2.returncode != 0:
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b"500 Cannot parse public key\n")
                        return
                    result3 = subprocess.run(
                        ['openssl', 'dgst', '-sha256', '-binary'],
                        input=result2.stdout, capture_output=True)
                    result4 = subprocess.run(
                        ['openssl', 'enc', '-base64', '-A'],
                        input=result3.stdout, capture_output=True)
                    fingerprint = result4.stdout.decode('utf-8', errors='ignore').strip()
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(fingerprint.encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"404 No certificate found\n")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Error: {str(e)}\n".encode('utf-8'))
            return

        # 路由 7.5: HMAC 密钥更新 (Key Rotation，仅 Master 下发，验签已在入口完成)
        elif req_path == '/setkey':
            import re
            new_key = query.get('key', [''])[0]
            # [安全] 严格 64 位 hex 白名单校验，封死注入与弱密钥
            if not re.fullmatch(r'[0-9a-fA-F]{64}', new_key):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"400 Bad Request: Invalid key format\n")
                return
            try:
                config_path = '/opt/ip_sentinel/config.conf'
                import fcntl
                with open(config_path, 'r+', encoding='utf-8', errors='ignore') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    lines = f.readlines()
                    found = False
                    for i, line in enumerate(lines):
                        if line.startswith('HMAC_SECRET='):
                            lines[i] = f'HMAC_SECRET="{new_key}"\n'
                            found = True
                            break
                    if not found:
                        lines.append(f'HMAC_SECRET="{new_key}"\n')
                    f.seek(0)
                    f.writelines(lines)
                    f.truncate()
                    fcntl.flock(f, fcntl.LOCK_UN)
                # [即时生效] 同步内存鉴权令牌，无需重启 daemon 即完成密钥轮换
                AUTH_TOKEN = new_key
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Action Accepted: setkey\n")
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Error: {str(e)}\n".encode('utf-8'))
            return

        # 路由 8: 功能模块动态起停 (Feature Flag API)
        elif req_path == '/trigger_toggle':
            mod_name = query.get('mod', [''])[0]
            target_state = query.get('state', [''])[0].lower()
            
            if mod_name not in ['google', 'trust'] or target_state not in ['true', 'false']:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"400 Bad Request: Invalid parameters\n")
                return
                
            config_key = f"ENABLE_{mod_name.upper()}="
            
            try:
                config_path = '/opt/ip_sentinel/config.conf'
                import fcntl
                
                with open(config_path, 'r+', encoding='utf-8', errors='ignore') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    lines = f.readlines()
                    
                    found = False
                    for i, line in enumerate(lines):
                        if line.startswith(config_key):
                            lines[i] = f'{config_key}"{target_state}"\n'
                            found = True
                            break
                            
                    if not found:
                        lines.append(f'{config_key}"{target_state}"\n')
                        
                    f.seek(0)
                    f.writelines(lines)
                    f.truncate()
                    fcntl.flock(f, fcntl.LOCK_UN)
                
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Action Accepted: trigger_toggle\n")
                
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Internal Error: {str(e)}\n".encode('utf-8'))

        # 路由 8: 零信任 OTA 远程热更新链路
        elif req_path == '/trigger_ota':
            try:
                # [P1-008] OTA 完整性校验：从查询参数中提取期望的 SHA256 哈希
                ota_params = urllib.parse.parse_qs(parsed.query)
                ota_expected_sha256 = ota_params.get('sha256', [''])[0]
                # [安全] 白名单校验：仅接受 64 位 hex，防止注入 ota_script
                # 注意：使用独立别名 _re 而非顶层 re，规避 do_GET 内其他路由局部 import re 引起的 UnboundLocalError
                import re as _re
                if ota_expected_sha256 and not _re.fullmatch(r'[0-9a-fA-F]{64}', ota_expected_sha256):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"400 Bad Request: Invalid sha256 format\n")
                    return
                
                config_mem = {}
                config_path = '/opt/ip_sentinel/config.conf'
                if os.path.exists(config_path):
                    with open(config_path, 'r', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if '=' in line and not line.startswith('#'):
                                key, val = line.split('=', 1)
                                config_mem[key] = val.strip('"\'')
                                
                # [OTA 熔断器 1] 核验 Agent 本地策略是否授予了更新权限
                if config_mem.get('ENABLE_OTA', 'false').lower() != 'true':
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden: OTA Upgrade Disabled locally\n")
                    return
                    
                # [OTA 熔断器 2] 检测官方网关硬编码限制，防范越权投毒
                if config_mem.get('TG_TOKEN', '') == 'OFFICIAL_GATEWAY_MODE':
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden: OTA strictly disabled under Public Gateway mode\n")
                    return
                    
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Action Accepted: trigger_ota\n")
                
                # [防线/容灾] 逃逸 Cgroup 隔离沙盒，并引入前置脚本语法校验防砖
                import base64
                repo_url = "https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/main"
                if os.path.exists('/opt/ip_sentinel/core/install.sh'):
                    with open('/opt/ip_sentinel/core/install.sh', 'r') as f:
                        for line in f:
                            if line.startswith('REPO_RAW_URL='):
                                repo_url = line.split('=', 1)[1].strip('"\'')
                                break
                
                err_msg = f"❌ **OTA 熔断告警**\n📍 节点: `{config_mem.get('NODE_ALIAS', '未知')}`\n⚠️ 原因: 脚本完整性校验未通过，下载可能不完整或被篡改。\n🔒 期望哈希: `{ota_expected_sha256 or '未提供'}`\n🚀 状态: 升级已取消，节点安全。"
                err_msg_b64 = base64.b64encode(err_msg.encode('utf-8')).decode('utf-8')
                
                tg_url = config_mem.get('TG_API_URL', '')
                chat_id = config_mem.get('CHAT_ID', '')
                
                # 将升级逻辑进行 Base64 深层封装，免疫 Popen 或 Systemd 传递带来的指令注入风险
                ota_script = f"""
trap 'rm -f -- "$0"' EXIT
export SILENT_OTA="true"
TMP_FILE="/tmp/ota_agent.sh"
if ! curl -fsSL --connect-timeout 10 --retry 2 {repo_url}/core/install.sh -o "$TMP_FILE" 2>/dev/null; then
    MSG=$(echo '{err_msg_b64}' | base64 -d)
    curl -s -m 10 -X POST "{tg_url}" -d "chat_id={chat_id}" --data-urlencode "text=$MSG" -d "parse_mode=Markdown" > /dev/null 2>&1
    echo "OTA Download Failed: Could not fetch install.sh" >> /opt/ip_sentinel/logs/ota_upgrade.log
    exit 1
fi
# [P1-008] OTA 完整性校验：SHA256 哈希对比
VERIFY_PASS=true
if [ -n "{ota_expected_sha256}" ] && [ -f "$TMP_FILE" ]; then
    DOWNLOADED_HASH=$(sha256sum "$TMP_FILE" | cut -d' ' -f1)
    if [ "$DOWNLOADED_HASH" != "{ota_expected_sha256}" ]; then
        VERIFY_PASS=false
        MSG=$(echo '{err_msg_b64}' | base64 -d)
        curl -s -m 10 -X POST "{tg_url}" -d "chat_id={chat_id}" --data-urlencode "text=$MSG" -d "parse_mode=Markdown" > /dev/null 2>&1
        echo "OTA Integrity Failed: SHA256 mismatch (expected: {ota_expected_sha256}, got: $DOWNLOADED_HASH)" > /opt/ip_sentinel/logs/ota_upgrade.log
    fi
fi
	if [ "$VERIFY_PASS" = true ] && [ -s "$TMP_FILE" ] && bash -n "$TMP_FILE"; then
    bash "$TMP_FILE" > /opt/ip_sentinel/logs/ota_upgrade.log 2>&1
else
    if [ "$VERIFY_PASS" = true ]; then
        MSG=$(echo '{err_msg_b64}' | base64 -d)
        curl -s -m 10 -X POST "{tg_url}" -d "chat_id={chat_id}" --data-urlencode "text=$MSG" -d "parse_mode=Markdown" > /dev/null 2>&1
        echo "OTA Checksum Failed: Script corrupted" > /opt/ip_sentinel/logs/ota_upgrade.log
    fi
fi
rm -f -- "$0"
"""
                ota_script_b64 = base64.b64encode(ota_script.encode('utf-8')).decode('utf-8')
                
                import tempfile
                import os as os_mod
                try:
                    decoded_script = base64.b64decode(ota_script_b64).decode('utf-8')
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, dir='/tmp') as f:
                        f.write(decoded_script)
                        f.flush()
                        os_mod.chmod(f.name, 0o700)
                        script_path = f.name
                    subprocess.Popen(["nohup", "bash", script_path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                except Exception as e:
                    print(f"OTA script execution failed: {e}")
                
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Internal Error: {str(e)}\n".encode('utf-8'))

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

import socket
# ----------------------------------------------------------
# [核心架构] 多线程非阻塞 Socket 模型 (抵抗 Slowloris 及阻塞攻击)
# ----------------------------------------------------------
class DualStackServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    _request_sem = threading.BoundedSemaphore(50)
    
    def process_request(self, request, client_address):
        # [P1-006] 线程数上限保护，防止资源耗尽
        if not self._request_sem.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)
    
    def finish_request(self, request, client_address):
        try:
            super().finish_request(request, client_address)
        finally:
            self._request_sem.release()
    
    def server_bind(self):
        # [核心魔改] 强行解除 Linux/Unix 的 IPv6 独占锁
        # 实现一个 Socket 对象同时接管 IPv4 (0.0.0.0) 和 IPv6 (::) 的全域监听防漏接机制
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                pass
        super().server_bind()

# [v4.2.2 终极架构] 彻底抛弃配置文件的 IP 束缚，强行探测系统底层的双栈能力
bind_addr = "::"
address_family = socket.AF_INET6
try:
    # 探针：如果机器是纯 IPv4 (连内核级的 IPv6 模块都没有被加载)，强绑 :: 会引发 OSError，此时自动降维
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.close()
except OSError:
    bind_addr = "0.0.0.0"
    address_family = socket.AF_INET

DualStackServer.address_family = address_family
httpd = DualStackServer((bind_addr, PORT), AgentHandler)

# ----------------------------------------------------------
# [加密通信] 强制全网挂载 TLS 加密隧道上下文
# ----------------------------------------------------------
import ssl
cert_path = '/opt/ip_sentinel/core/cert.pem'
key_path = '/opt/ip_sentinel/core/key.pem'

if os.path.exists(cert_path) and os.path.exists(key_path):
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    except Exception as e:
        print(f"SSL 隧道构建失败，退化为 HTTP: {e}")

try:
    httpd.serve_forever()
except Exception as e:
    sys.exit(1)
EOF

echo "🚀 [Agent] 正在启动 Webhook 监听服务 (端口: $AGENT_PORT)..."
exec python3 "${INSTALL_DIR}/core/webhook.py" "$AGENT_PORT"