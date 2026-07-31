#!/bin/bash

# ==========================================================
# 脚本名称: updater.sh
# 核心功能: 指纹防惊群错峰轮换、LBS 底层静默分发、深度探针签名防伪
# ==========================================================

trap 'rm -f /tmp/ip_sentinel_* 2>/dev/null' EXIT

INSTALL_DIR="/opt/ip_sentinel"
CONFIG_FILE="${INSTALL_DIR}/config.conf"
UA_TIME_FILE="${INSTALL_DIR}/core/.ua_last_update"

REPO_RAW_URL="https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/main"

# --- [底层数据链装载] ---
if [ ! -f "$CONFIG_FILE" ]; then
    exit 1
fi
source "$CONFIG_FILE"

# --- [全局态势日志系统] ---
log() {
    local local_ver="${AGENT_VERSION:-未知}"
    
    mkdir -p "${INSTALL_DIR}/logs"

    local core_msg=$(printf "[v%-5s] [%-5s] [%-7s] [%s] %s" "$local_ver" "$2" "$1" "$REGION_CODE" "$3")
    # 强制剔除节点宿主机本地时差，严格对齐指挥部 UTC 基准
    echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $core_msg" >> "$LOG_FILE"

    if command -v logger >/dev/null 2>&1; then
        logger -t ip-sentinel "$core_msg"
    else
        echo "$core_msg"
    fi
}

log "Updater" "INFO " "========== 触发后台静默 OTA 热数据更新 =========="

# ==========================================================
# [网络路由锁定] 构建强锚定出站屏障，彻底阻断跨协议溢出逃逸
# ==========================================================
CURL_ARGS=("-${IP_PREF:-4}" "-sL")

if [ -n "$BIND_IP" ]; then
    RAW_BIND_IP=$(echo "$BIND_IP" | tr -d '[]')
    if ! ip addr show 2>/dev/null | grep -qw "$RAW_BIND_IP"; then
        log "Updater" "WARN " "检测到绑定的出口 IP ($RAW_BIND_IP) 已丢失，自动退回默认路由！"
    else
        CURL_ARGS+=("--interface" "$RAW_BIND_IP")
    fi
fi

# ==========================================================
# [指纹池滚动更新] 错峰调度防惊群风暴算法
# 强制设定 30 天超长冷静期以规避 Github 限流与特征同构
# ==========================================================
NOW=$(date +%s)
LAST_UPDATE=0

if [ -f "$UA_TIME_FILE" ]; then
    LAST_UPDATE=$(cat "$UA_TIME_FILE" | tr -d '\r\n')
fi

if ! [[ "$LAST_UPDATE" =~ ^[0-9]+$ ]]; then
    LAST_UPDATE=0
fi

DIFF=$((NOW - LAST_UPDATE))

if [ "$DIFF" -ge 2592000 ] || [ "$LAST_UPDATE" -eq 0 ]; then
    TMP_UA="/tmp/ip_sentinel_ua.txt"
    curl "${CURL_ARGS[@]}" "${REPO_RAW_URL}/data/user_agents.txt" -o "$TMP_UA"
    
    if [ -s "$TMP_UA" ]; then
        mv "$TMP_UA" "${INSTALL_DIR}/data/user_agents.txt"
        echo "$NOW" > "$UA_TIME_FILE"
        log "Updater" "INFO " "✅ 设备指纹池 (User-Agents) 30天错峰滚动更新成功"
    else
        log "Updater" "WARN " "❌ UA 池拉取失败，保留本地旧数据防崩溃"
        rm -f "$TMP_UA"
    fi
else
    DAYS_LEFT=$(((2592000 - DIFF) / 86400))
    log "Updater" "INFO " "⏳ 设备指纹池处于 30 天静默期 (剩余约 ${DAYS_LEFT} 天)，跳过拉取"
fi

# ----------------------------------------------------------
# [态势感知热更] 动态注入本土高权热搜及战区 LBS 规则
# ----------------------------------------------------------
TMP_KW="/tmp/ip_sentinel_kw.txt"
curl "${CURL_ARGS[@]}" "${REPO_RAW_URL}/data/keywords/kw_${REGION_CODE}.txt" -o "$TMP_KW"

if [ -s "$TMP_KW" ]; then
    mv "$TMP_KW" "${INSTALL_DIR}/data/keywords/kw_${REGION_CODE}.txt"
    log "Updater" "INFO " "✅ 区域搜索词库 (kw_${REGION_CODE}) 每日同步成功"
else
    log "Updater" "WARN " "❌ 搜索词库拉取失败，保留本地旧数据防崩溃"
    rm -f "$TMP_KW"
fi

REGION_JSON_FILE=$(find "${INSTALL_DIR}/data/regions" -name "*.json" 2>/dev/null | head -n 1)

if [ -n "$REGION_JSON_FILE" ] && [ -f "$REGION_JSON_FILE" ]; then
    REL_PATH=${REGION_JSON_FILE#*${INSTALL_DIR}/}
    TMP_JSON="/tmp/ip_sentinel_region.json"
    
    curl "${CURL_ARGS[@]}" "${REPO_RAW_URL}/${REL_PATH}" -o "$TMP_JSON"
    
    if [ -s "$TMP_JSON" ]; then
        mv "$TMP_JSON" "$REGION_JSON_FILE"
        log "Updater" "INFO " "✅ 核心战区规则库 ($REL_PATH) 每日同步成功"
    else
        log "Updater" "WARN " "❌ 战区规则库拉取失败，保留本地旧数据"
        rm -f "$TMP_JSON"
    fi
fi

# ==========================================================
# [容灾校验] SHA256 完整性校验与供应链投毒防线
# ==========================================================
TMP_PROBE="/tmp/ip_sentinel_probe.sh"
TMP_PROBE_SRC2="/tmp/ip_sentinel_probe_src2.sh"
PROBE_HASH_FILE="${INSTALL_DIR}/core/.probe_hash"
PROBE_PRIMARY_URL="https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh"
PROBE_BACKUP_URL="https://IP.Check.Place"

# 加载已锁定的探针哈希
PROBE_EXPECTED_HASH=""
if [ -f "$PROBE_HASH_FILE" ]; then
    PROBE_EXPECTED_HASH=$(cat "$PROBE_HASH_FILE" | tr -d '[:space:]')
fi

# 从主源拉取探针脚本
curl "${CURL_ARGS[@]}" "$PROBE_PRIMARY_URL" -o "$TMP_PROBE"

# [多源交叉验证] 主源与备用源独立下载，内容哈希一致才判定为可信内容
probe_fetch_cross_verify() {
    local primary_file="$1"
    if [ ! -s "$primary_file" ]; then
        return 1
    fi
    # 先用原有 "xykt" 标记做基本过滤（防 HTML 劫持页）
    if ! grep -q "xykt" "$primary_file" 2>/dev/null; then
        return 1
    fi

    # 从备用源独立下载做二次交叉验证
    curl "${CURL_ARGS[@]}" "$PROBE_BACKUP_URL" -o "$TMP_PROBE_SRC2"
    if [ ! -s "$TMP_PROBE_SRC2" ]; then
        log "Updater" "WARN " "⚠️ 备用源 ($PROBE_BACKUP_URL) 拉取失败，本次探针更新挂起，保留本地旧版本"
        return 1
    fi
    if ! grep -q "xykt" "$TMP_PROBE_SRC2" 2>/dev/null; then
        log "Updater" "WARN " "⚠️ 备用源内容不含合法 xykt 标记，双源交叉验证不通过，本次探针更新挂起"
        return 1
    fi

    # 双源内容哈希比对：一致 → 内容可信；不一致 → 疑似投毒
    local primary_hash=$(sha256sum "$primary_file" | cut -d' ' -f1)
    local backup_hash=$(sha256sum "$TMP_PROBE_SRC2" | cut -d' ' -f1)
    if [ "$primary_hash" != "$backup_hash" ]; then
        log "Updater" "WARN " "🚨 多源哈希不一致 ($primary_hash ≠ $backup_hash)，可能遭遇投毒，请人工确认"
        return 1
    fi
    return 0
}

# [P1-003] SHA256 完整性校验
verify_probe_update() {
    local tmp_file="$1"
    local actual_hash

    # 基本合法性过滤 + 双源交叉验证（投毒防线）
    if ! probe_fetch_cross_verify "$tmp_file"; then
        return 1
    fi

    actual_hash=$(sha256sum "$tmp_file" | cut -d' ' -f1)

    if [ -z "$PROBE_EXPECTED_HASH" ]; then
        # [首次锁定] 无已锁定哈希时，内容合法即锁定
        echo "$actual_hash" > "$PROBE_HASH_FILE"
        log "Updater" "INFO " "🔒 探针脚本哈希首次锁定: $actual_hash"
        return 0
    fi

    # [有锁续期] 与已锁定哈希比对：一致 → 接受并保持锁定
    if [ "$actual_hash" = "$PROBE_EXPECTED_HASH" ]; then
        echo "$actual_hash" > "$PROBE_HASH_FILE"
        return 0
    fi

    # [变化挂起] 哈希变化且双源一致 → 可能是合法上游更新，也可能双源同时被投毒。
    # 不自动重锁，保留旧版本，需人工确认后手动清理 .probe_hash 完成重锁
    log "Updater" "WARN " "🛑 探针哈希变化 ($PROBE_EXPECTED_HASH → $actual_hash)，可能是上游更新或投毒，本次保留旧版本，请人工确认后手动清理 .probe_hash 重锁"
    return 1
}

if verify_probe_update "$TMP_PROBE"; then
    mv "$TMP_PROBE" "${INSTALL_DIR}/core/ip_probe.sh"
    chmod +x "${INSTALL_DIR}/core/ip_probe.sh"
    log "Updater" "INFO " "✅ 深海声呐底层探针 (ip_probe.sh) SHA256 完整性校验通过"
else
    log "Updater" "WARN " "❌ 探针源文件拉取受损或遭投毒劫持，已触发防砖机制，保留本地旧版本"
    rm -f "$TMP_PROBE" "$TMP_PROBE_SRC2" 2>/dev/null
fi

# ==========================================================
# [空间瘦身] 长效健康清理与爆栈预防机制
# ==========================================================
if [ -f "$LOG_FILE" ]; then
    tail -n 2000 "$LOG_FILE" > "${LOG_FILE}.tmp"
    mv "${LOG_FILE}.tmp" "$LOG_FILE"
    log "Updater" "INFO " "🧹 系统日志已完成定期清理瘦身 (保留最新 2000 行)"
fi

log "Updater" "INFO " "========== OTA 养料注入与系统维护结束 =========="