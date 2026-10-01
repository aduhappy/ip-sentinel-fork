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

# [权限鉴权] 验签密钥优先级：HMAC_SECRET（Master 已下发）> PAIR_KEY（安装时生成的配对密钥）> CHAT_ID（仅旧版未配对节点兼容）
# PAIR_KEY 只随注册暗号经用户自己的 Telegram 会话交给 Master；CHAT_ID 是公开信息，新装节点不再以其作为验签密钥
AUTH_TOKEN = ""
CHAT_ID = ""
PAIR_KEY = ""
if os.path.exists('/opt/ip_sentinel/config.conf'):
    _cfg = {}
    with open('/opt/ip_sentinel/config.conf', 'r') as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                _cfg.setdefault(k, v.strip('"\''))
    CHAT_ID = _cfg.get('CHAT_ID', '')
    if re.fullmatch(r'[0-9a-f]{64}', _cfg.get('PAIR_KEY', '')):
        PAIR_KEY = _cfg['PAIR_KEY']
    AUTH_TOKEN = _cfg.get('HMAC_SECRET', '') or PAIR_KEY or CHAT_ID

CONFIG_PATH = '/opt/ip_sentinel/config.conf'
LOG_PATH = '/opt/ip_sentinel/logs/sentinel.log'
MASTER_POLLED_FILE = '/opt/ip_sentinel/core/.master_polled'

def read_config():
    """读取 config.conf 为 dict（同名键取首次出现，与 /setkey 的覆写语义一致）"""
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    cfg.setdefault(k, v.strip('"\''))
    return cfg

def update_config(pairs):
    """flock 独占锁下原子覆写/追加配置项；值须已通过白名单校验"""
    import fcntl
    with open(CONFIG_PATH, 'r+', encoding='utf-8', errors='ignore') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        lines = f.readlines()
        for key, val in pairs:
            prefix = f"{key}="
            for i, line in enumerate(lines):
                if line.startswith(prefix):
                    lines[i] = f'{prefix}"{val}"\n'
                    break
            else:
                lines.append(f'{prefix}"{val}"\n')
        f.seek(0)
        f.writelines(lines)
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)

def detect_egress(fam):
    """探测指定地址族的公网出口：返回 (public_ip, bind_ip, error)。
    拒绝经 WARP/隧道等虚拟网卡的出口（养护它们没有意义）；本机网卡上不存在该地址时（NAT）bind_ip 为空，交由内核路由。"""
    import ipaddress
    probe_target = '8.8.8.8' if fam == '4' else '2001:4860:4860::8888'
    try:
        route = subprocess.run(['ip', f'-{fam}', 'route', 'get', probe_target],
                               capture_output=True, text=True, timeout=3).stdout
    except Exception:
        route = ''
    if not route.strip():
        return '', '', f'本机没有 IPv{fam} 默认路由'
    m = re.search(r'\bdev (\S+)', route)
    dev = m.group(1) if m else ''
    if re.match(r'^(warp|wgcf|tun|tap|docker|br-|lo)', dev):
        return '', '', f'IPv{fam} 出口经由虚拟网卡 {dev}（WARP/隧道），不予养护'
    ip_str = ''
    for url in ('https://api.ip.sb/ip', 'https://ifconfig.me'):
        try:
            out = subprocess.run(['curl', f'-{fam}', '-s', '-m', '4', url],
                                 capture_output=True, text=True, timeout=6).stdout.strip()
        except Exception:
            out = ''
        if out:
            ip_str = out
            break
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return '', '', f'IPv{fam} 公网出口探测失败'
    if ip_obj.version != int(fam) or not ip_obj.is_global:
        return '', '', f'IPv{fam} 出口 {ip_str} 不是公网地址'
    try:
        addrs = subprocess.run(['ip', f'-{fam}', 'addr', 'show'], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        addrs = ''
    bind_ip = ip_str if re.search(r'inet6? ' + re.escape(ip_str) + r'/', addrs) else ''
    return ip_str, bind_ip, ''

def build_report_data():
    """汇总本节点近 24 小时养护数据（只读配置与日志，不发起外部请求，供司令部快速拉取）"""
    import collections
    import datetime
    cfg = read_config()
    mode = cfg.get('MAINT_FAMILY', '')
    legacy_fam = cfg.get('IP_PREF', '4') if cfg.get('IP_PREF', '4') in ('4', '6') else '4'
    if mode == 'dual':
        fams = ['4', '6']
    elif mode in ('4', '6'):
        fams = [mode]
    else:
        fams = [legacy_fam]

    def fam_ip(f):
        if mode and cfg.get(f'PUBLIC_IP{f}'):
            return cfg.get(f'PUBLIC_IP{f}')
        return cfg.get('PUBLIC_IP', '').strip('[]') if f == legacy_fam else ''

    stats = {f: {'ip': fam_ip(f),
                 'google': {'total': 0, 'ok': 0, 'fail': 0, 'warn': 0, 'last': '', 'last_time': ''},
                 'trust': {'total': 0, 'ok': 0, 'fail': 0}} for f in fams}
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
    line_re = re.compile(r'^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC\] \[v[^\]]*\] \[([^\]]*)\] \[(Google|Trust)\s*([46]?)\s*\]')
    lines = collections.deque(maxlen=20000)
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, 'r', errors='ignore') as f:
            for line in f:
                lines.append(line)
    for line in lines:
        m = line_re.match(line)
        if not m:
            continue
        try:
            ts = datetime.datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
        if ts < cutoff:
            continue
        level, mod, fam = m.group(2).strip(), m.group(3), (m.group(4) or legacy_fam)
        if fam not in stats:
            continue
        bucket = stats[fam]['google' if mod == 'Google' else 'trust']
        if level == 'START':
            bucket['total'] += 1
        if '✅' in line:
            bucket['ok'] += 1
        if '❌' in line:
            bucket['fail'] += 1
        if mod == 'Google' and '⚠️' in line:
            bucket['warn'] += 1
        if mod == 'Google' and level == 'SCORE' and '自检结论: ' in line:
            bucket['last'] = line.split('自检结论: ', 1)[1].strip()
            bucket['last_time'] = m.group(1)
    return {
        'node': cfg.get('NODE_NAME', ''),
        'alias': cfg.get('NODE_ALIAS', cfg.get('NODE_NAME', '')),
        'region': cfg.get('REGION_CODE', ''),
        'region_name': cfg.get('REGION_NAME', ''),
        'version': cfg.get('AGENT_VERSION', ''),
        'mode': mode or legacy_fam,
        'google_enabled': cfg.get('ENABLE_GOOGLE', 'true') == 'true',
        'trust_enabled': cfg.get('ENABLE_TRUST', 'true') == 'true',
        'families': stats,
    }

def cert_pubkey_pin():
    """本机 TLS 公钥 (DER) 的 SHA256 base64，与 /cert_fp 及 Master --pinnedpubkey 同格式；失败返回空串"""
    cert_path = '/opt/ip_sentinel/core/cert.pem'
    try:
        if not os.path.exists(cert_path):
            return ''
        pem = subprocess.run(['openssl', 'x509', '-pubkey', '-in', cert_path, '-noout'], capture_output=True)
        if pem.returncode != 0:
            return ''
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=pem.stdout, capture_output=True)
        if der.returncode != 0 or not der.stdout:
            return ''
        import base64
        return base64.b64encode(hashlib.sha256(der.stdout).digest()).decode('ascii')
    except Exception:
        return ''

class AgentHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global AUTH_TOKEN, CHAT_ID
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
                # [HMAC v2] 签名覆盖路径 + 全部业务参数（除 t/sign 外），防止中间人篡改 key/sha256/mod/b64 等参数；
                # 规范化算法与 Master canonical_query 一致：按 & 拆分原始查询串 → 剔除空段 → 排序 → 以 & 拼接
                biz_params = [p for p in parsed.query.split('&') if p and p.split('=', 1)[0] not in ('t', 'sign')]
                sign_msgs = [f"v2:{req_path}?{'&'.join(sorted(biz_params))}:{req_t}".encode('utf-8')]
                # v1 旧格式（仅签路径）只对不携带业务参数的请求放行：无可篡改内容，同时保持旧版 Master 基础指令可用
                if not biz_params:
                    sign_msgs.append(f"{req_path}:{req_t}".encode('utf-8'))

                def sign_matches(key):
                    for msg in sign_msgs:
                        expected_sign = hmac.new(key.encode('utf-8'), msg, hashlib.sha256).hexdigest()
                        if hmac.compare_digest(expected_sign, req_sign):
                            return True
                    return False

                sign_ok = sign_matches(AUTH_TOKEN)

                # [配对引导] /setkey 与 /cert_fp 额外接受 PAIR_KEY 签名：Master 重装或更换密钥后，
                # 凭用户转发的注册暗号（携带 PAIR_KEY）即可重新配对，无需重装 Agent
                if not sign_ok and PAIR_KEY and req_path in ('/setkey', '/cert_fp'):
                    sign_ok = sign_matches(PAIR_KEY)

                # [HMAC 密钥同步] 旧版未配对节点（无 HMAC_SECRET 与 PAIR_KEY，AUTH_TOKEN 即 CHAT_ID）的 /setkey 引导验签。
                # [安全] 引导仅当 AUTH_TOKEN 仍等于 CHAT_ID（密钥尚未轮换的初始状态）时有效；
                # 一旦 setkey 成功轮换，AUTH_TOKEN != CHAT_ID 后引导立即关闭，
                # 堵死"CHAT_ID 泄露 → 离线伪造 /setkey 轮换密钥"的节点失联攻击。
                if not sign_ok and req_path == '/setkey' and AUTH_TOKEN == CHAT_ID:
                    try:
                        sign_ok = sign_matches(str(CHAT_ID))
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
            # --manual：手动触发的单机战报不受"司令部已统一汇总"的定时抑制
            subprocess.Popen(["nohup", "bash", "/opt/ip_sentinel/core/tg_report.sh", "--manual"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

        # 路由 3.5: 司令部汇总数据拉取（只读配置与日志，快速返回 JSON；记录拉取时间供定时战报去重）
        elif req_path == '/report_data':
            try:
                import json
                body = json.dumps(build_report_data(), ensure_ascii=False).encode('utf-8')
                try:
                    with open(MASTER_POLLED_FILE, 'w') as f:
                        f.write(str(int(time.time())))
                except Exception:
                    pass
                self.send_response(200)
                self.send_header("Content-type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Internal Error: {str(e)}\n".encode('utf-8'))
            return

        # 路由 3.6: 养护地址族切换（4 / 6 / dual），由司令部下发
        elif req_path == '/trigger_ipmode':
            mode = query.get('mode', [''])[0]
            if mode not in ('4', '6', 'dual'):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"400 Bad Request: Invalid mode\n")
                return
            try:
                fams = ['4', '6'] if mode == 'dual' else [mode]
                pairs = [('MAINT_FAMILY', mode)]
                found = []
                for fam in fams:
                    pub, bind, err = detect_egress(fam)
                    if err:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(f"400 Bad Request: {err}\n".encode('utf-8'))
                        return
                    pairs += [(f'PUBLIC_IP{fam}', pub), (f'BIND_IP{fam}', bind)]
                    found.append(f"v{fam}={pub}")
                update_config(pairs)
                self.send_response(200)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"Action Accepted: ipmode={mode}; {'; '.join(found)}\n".encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Internal Error: {str(e)}\n".encode('utf-8'))
            return

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
                ota_expected_sha256 = ota_params.get('sha256', [''])[0].lower()
                # [安全] 白名单校验：仅接受 64 位 hex，防止注入 ota_script
                # [安全] 哈希为必填项：缺失即拒绝，杜绝"无哈希 → 跳过完整性校验"的静默降级
                # 注意：使用独立别名 _re 而非顶层 re，规避 do_GET 内其他路由局部 import re 引起的 UnboundLocalError
                import re as _re
                if not _re.fullmatch(r'[0-9a-f]{64}', ota_expected_sha256):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"400 Bad Request: Missing or invalid sha256\n")
                    return
                # [OTA 版本锁定] 可选的提交 SHA（Master 解析分支得出）：存在时须为 40 位 hex，安装全程从该不可变提交拉取
                ota_ref = ota_params.get('ref', [''])[0].lower()
                if ota_ref and not _re.fullmatch(r'[0-9a-f]{40}', ota_ref):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"400 Bad Request: Invalid ref\n")
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
                                repo_url = line.strip().split('=', 1)[1].strip('"\'')
                                break
                
                # [OTA 版本锁定] GitHub Raw 地址把分支段替换为提交 SHA，并通过 OTA_PINNED_REF 让 install.sh 后续拉取
                # 的全部文件同样锁定该提交，避免 Raw 缓存导致新旧文件混装；非 GitHub Raw 地址（自建镜像）维持原分支拉取
                fetch_url = repo_url
                pinned_ref = ''
                pin_match = _re.fullmatch(r'(https://raw\.githubusercontent\.com/[^/]+/[^/]+)/[^/]+', repo_url)
                if ota_ref and pin_match:
                    fetch_url = f"{pin_match.group(1)}/{ota_ref}"
                    pinned_ref = ota_ref
                
                err_msg = f"❌ **OTA 熔断告警**\n📍 节点: `{config_mem.get('NODE_ALIAS', '未知')}`\n⚠️ 原因: 脚本完整性校验未通过，下载可能不完整或被篡改。\n🔒 期望哈希: `{ota_expected_sha256}`\n🚀 状态: 升级已取消，节点安全。"
                err_msg_b64 = base64.b64encode(err_msg.encode('utf-8')).decode('utf-8')
                
                tg_url = config_mem.get('TG_API_URL', '')
                chat_id = config_mem.get('CHAT_ID', '')
                
                # 将升级逻辑进行 Base64 深层封装，免疫 Popen 或 Systemd 传递带来的指令注入风险
                ota_script = f"""
trap 'rm -f -- "$0"' EXIT
export SILENT_OTA="true"
export OTA_PINNED_REF="{pinned_ref}"
TMP_FILE="/tmp/ota_agent.sh"
if ! curl -fsSL --connect-timeout 10 --retry 2 {fetch_url}/core/install.sh -o "$TMP_FILE" 2>/dev/null; then
    MSG=$(echo '{err_msg_b64}' | base64 -d)
    curl -s -m 10 -X POST "{tg_url}" -d "chat_id={chat_id}" --data-urlencode "text=$MSG" -d "parse_mode=Markdown" > /dev/null 2>&1
    echo "OTA Download Failed: Could not fetch install.sh" >> /opt/ip_sentinel/logs/ota_upgrade.log
    exit 1
fi
# [P1-008] OTA 完整性校验：SHA256 哈希对比
VERIFY_PASS=true
if [ -f "$TMP_FILE" ]; then
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

        # 路由 9: 全舰队 Bot 凭证切换 (移植自上游 #102，按 fork 安全模型改造)
        elif req_path == '/trigger_reconfig':
            # 注意：do_GET 内任何 "import X" 都会令 X 成为整个函数的局部名；此处若写 import urllib.error 会遮蔽
            # 顶层 urllib，使所有请求在入口 urllib.parse 处 UnboundLocalError；re 同理须在本分支内导入
            import re
            import json
            import base64
            import fcntl
            from urllib.error import HTTPError
            b64_payload = query.get('b64', [''])[0]
            if not b64_payload:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"400 Bad Request: Missing payload\n")
                return
            try:
                # [防线/容灾] 还原 URL 安全 Base64 载荷（载荷已被 v2 签名完整覆盖，无法被中间人篡改）
                pad = len(b64_payload) % 4
                if pad > 0:
                    b64_payload += '=' * (4 - pad)
                b64_payload = b64_payload.replace('-', '+').replace('_', '/')
                payload = json.loads(base64.b64decode(b64_payload).decode('utf-8'))
                new_token = str(payload.get('token', '')).strip()
                new_chat_id = str(payload.get('chat_id', '')).strip()

                # [格式清洗] 强校验凭证形态，屏蔽注入与手误（token 会写入配置与 URL）
                if not re.fullmatch(r'\d{6,}:[A-Za-z0-9_-]{30,}', new_token):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"400 Bad Request: Invalid token format\n")
                    return
                if not re.fullmatch(r'-?\d{5,}', new_chat_id):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"400 Bad Request: Invalid chat id\n")
                    return

                config_mem = {}
                config_path = '/opt/ip_sentinel/config.conf'
                if os.path.exists(config_path):
                    with open(config_path, 'r', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if '=' in line and not line.startswith('#'):
                                key, val = line.split('=', 1)
                                config_mem.setdefault(key, val.strip('"\''))

                # [熔断器] 复用 OTA 授权作为切换闸门（与 Master 下发范围对齐）
                if config_mem.get('ENABLE_OTA', 'false').lower() != 'true':
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden: Reconfig disabled (ENABLE_OTA=false)\n")
                    return

                local_ver = config_mem.get('AGENT_VERSION', 'unknown')

                def tg_api_call(url, body=None):
                    headers = {'User-Agent': f'IP-Sentinel-Agent/{local_ver}'}
                    data = None
                    if body is not None:
                        data = json.dumps(body).encode('utf-8')
                        headers['Content-Type'] = 'application/json'
                    req = urllib.request.Request(url, data=data, headers=headers)
                    try:
                        return json.loads(urllib.request.urlopen(req, timeout=8).read().decode('utf-8'))
                    except HTTPError as he:
                        # TG 对无效凭证返回 HTTP 401，解析响应体回传真实原因
                        try:
                            return json.loads(he.read().decode('utf-8'))
                        except Exception:
                            return {'ok': False, 'description': f'HTTP {he.code}'}
                    except Exception as ne:
                        return {'ok': False, 'description': str(ne)}

                # [步骤 1] getMe 验证新 Bot Token
                me_resp = tg_api_call(f"https://api.telegram.org/bot{new_token}/getMe")
                if not me_resp.get('ok'):
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(f"403 Forbidden: New bot getMe failed: {me_resp.get('description', 'unknown')}\n".encode('utf-8'))
                    return

                # [步骤 2] 先向新 Bot 推送注册暗号（失败则旧凭证保持完好）。
                # 采用 fork 的 10 字段格式：携带 PAIR_KEY 与证书指纹，新司令部（即便部署在新机器、HMAC_SECRET 不同）
                # 也能凭配对密钥完成握手并固定证书；无 PAIR_KEY 的旧节点按 8 字段发送
                pair_key = PAIR_KEY
                reg_fields = [
                    '#REGISTER#',
                    config_mem.get('REGION_CODE', 'UNKNOWN'),
                    config_mem.get('NODE_NAME', ''),
                    config_mem.get('COMM_IP', config_mem.get('PUBLIC_IP', '')),
                    config_mem.get('AGENT_PORT', ''),
                    config_mem.get('NODE_ALIAS', config_mem.get('NODE_NAME', '')),
                    config_mem.get('ENABLE_OTA', 'false'),
                    local_ver,
                ]
                if pair_key:
                    reg_fields += [pair_key, cert_pubkey_pin()]
                reg_msg = '|'.join(reg_fields)
                send_resp = tg_api_call(
                    f"https://api.telegram.org/bot{new_token}/sendMessage",
                    {'chat_id': new_chat_id,
                     'text': f"🔁 IP-Sentinel 节点已切换至本 Bot，请将下面的注册暗号转发给本 Bot 完成入库：\n\n{reg_msg}"}
                )
                if not send_resp.get('ok'):
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(f"403 Forbidden: Registration push failed: {send_resp.get('description', 'unknown')}\n".encode('utf-8'))
                    return

                # [步骤 3] flock 独占锁原子重写本地凭证三件套
                with open(config_path, 'r+', encoding='utf-8', errors='ignore') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    lines = f.readlines()
                    for key, new_val in (('TG_TOKEN', new_token),
                                         ('CHAT_ID', new_chat_id),
                                         ('TG_API_URL', f"https://api.telegram.org/bot{new_token}/sendMessage")):
                        prefix = f"{key}="
                        for i, line in enumerate(lines):
                            if line.startswith(prefix):
                                lines[i] = f'{prefix}"{new_val}"\n'
                                break
                        else:
                            lines.append(f'{prefix}"{new_val}"\n')
                    f.seek(0)
                    f.writelines(lines)
                    f.truncate()
                    fcntl.flock(f, fcntl.LOCK_UN)

                # [步骤 4] 内存态同步，无需重启守护进程：fork 验签不依赖 CHAT_ID，
                # 仅旧版未配对节点（AUTH_TOKEN 即 CHAT_ID）需随之切换验签密钥
                if AUTH_TOKEN == CHAT_ID:
                    AUTH_TOKEN = new_chat_id
                CHAT_ID = new_chat_id

                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(f"Action Accepted: trigger_reconfig; pairing={'yes' if pair_key else 'no'}\n".encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"500 Internal Error: {str(e)}\n".encode('utf-8'))
            return

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