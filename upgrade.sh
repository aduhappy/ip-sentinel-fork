#!/bin/bash
# ==========================================================
# IP-Sentinel 一键备份升级脚本 — hardened 分支
# 用法: bash <(curl -fsSL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/upgrade.sh)
# 支持同一台机器上 Master + Agent 并存（主子同体）
# ==========================================================
set -euo pipefail

# ==========================================================
# 颜色与辅助函数
# ==========================================================
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step()  { echo -e "\n${CYAN}========== $1 ==========${NC}"; }

REPO_RAW_URL="https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened"

# 全局变量
HAS_MASTER=false
HAS_AGENT=false
MASTER_VER=""
AGENT_VER=""
MASTER_TARGET=""
AGENT_TARGET=""
OLD_NODE_NAME=""
BACKUP_DIR=""

# ==========================================================
# 中断处理
# ==========================================================
cleanup_and_exit() {
    echo -e "\n\n${YELLOW}⚠️  检测到中断信号 (Ctrl+C)，升级操作已被手动中止。${NC}"
    echo -e "💡 现有安装未被修改，备份尚未创建。"
    exit 1
}
trap cleanup_and_exit INT QUIT TERM

# ==========================================================
# 1. 环境检测
# ==========================================================
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "请以 root 权限运行。"
        echo -e "💡 请切换到 root 用户 (执行 su root 或 sudo -i) 后重新运行。"
        exit 1
    fi
    info "Root 权限检查通过。"
}

check_network() {
    echo -n "🌐 正在检查 hardened 分支网络连通性..."
    if ! curl -sfL --connect-timeout 5 "${REPO_RAW_URL}/version.txt?t=$(date +%s)" > /dev/null 2>&1; then
        echo -e " ${RED}失败${NC}"
        error "无法连接 GitHub Raw (${REPO_RAW_URL})，请检查网络或代理设置。"
        echo -e "💡 如果在中国大陆 VPS，请尝试配置 GitHub 镜像或使用代理。"
        exit 1
    fi
    echo -e " ${GREEN}通过${NC}"
}

check_commands() {
    local missing=0
    for cmd in python3 curl openssl; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            error "必要命令 '$cmd' 未安装。"
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo -e "💡 请先安装缺失的命令后重试。"
        exit 1
    fi
    info "必要命令检查通过。"
}

version_lt() {
    test "$(printf '%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" && test "$1" != "$2"
}

detect_roles() {
    step "Step 1: 环境检测"

    # 独立检测 Master 和 Agent（互不排斥）
    if [ -f "/opt/ip_sentinel_master/master.conf" ]; then
        HAS_MASTER=true
        MASTER_VER=$(grep "^MASTER_VERSION=" "/opt/ip_sentinel_master/master.conf" 2>/dev/null | cut -d'"' -f2 || true)
        MASTER_VER="${MASTER_VER:-未知}"
        info "检测到 Master (v${MASTER_VER})"
    fi

    if [ -f "/opt/ip_sentinel/config.conf" ]; then
        HAS_AGENT=true
        AGENT_VER=$(grep "^AGENT_VERSION=" "/opt/ip_sentinel/config.conf" 2>/dev/null | cut -d'"' -f2 || true)
        OLD_NODE_NAME=$(grep "^NODE_NAME=" "/opt/ip_sentinel/config.conf" 2>/dev/null | cut -d'"' -f2 || true)
        AGENT_VER="${AGENT_VER:-未知}"
        info "检测到 Agent (v${AGENT_VER})"
    fi

    if ! $HAS_MASTER && ! $HAS_AGENT; then
        error "未检测到已安装的 IP-Sentinel（Master 或 Agent）。"
        echo -e "💡 请确认以下路径之一存在："
        echo -e "   - /opt/ip_sentinel_master/master.conf (Master)"
        echo -e "   - /opt/ip_sentinel/config.conf (Agent)"
        exit 1
    fi

    if $HAS_MASTER && $HAS_AGENT; then
        info "检测到主子同体（Master + Agent 共存），将依次升级 Master → Agent。"
    fi

    # 获取目标版本
    local version_txt
    version_txt=$(curl -sfL "${REPO_RAW_URL}/version.txt?t=$(date +%s)" 2>/dev/null || true)

    if $HAS_MASTER; then
        MASTER_TARGET=$(echo "$version_txt" | grep "^MASTER_VERSION=" | cut -d'=' -f2 | tr -d '[:space:]' || true)
        MASTER_TARGET="${MASTER_TARGET:-未知}"
        info "Master 当前: v${MASTER_VER} → 目标: v${MASTER_TARGET}"
    fi
    if $HAS_AGENT; then
        AGENT_TARGET=$(echo "$version_txt" | grep "^AGENT_VERSION=" | cut -d'=' -f2 | tr -d '[:space:]' || true)
        AGENT_TARGET="${AGENT_TARGET:-未知}"
        info "Agent 当前: v${AGENT_VER} → 目标: v${AGENT_TARGET}"
    fi

    # 版本比较（给出警告但允许继续）
    if $HAS_MASTER && [ "$MASTER_VER" != "未知" ] && [ "$MASTER_TARGET" != "未知" ]; then
        if ! version_lt "$MASTER_VER" "$MASTER_TARGET"; then
            warn "Master 已是最新 (v${MASTER_VER} >= v${MASTER_TARGET})"
        fi
    fi
    if $HAS_AGENT && [ "$AGENT_VER" != "未知" ] && [ "$AGENT_TARGET" != "未知" ]; then
        if ! version_lt "$AGENT_VER" "$AGENT_TARGET"; then
            warn "Agent 已是最新 (v${AGENT_VER} >= v${AGENT_TARGET})"
        fi
    fi
}

# ==========================================================
# 2. 备份
# ==========================================================
do_backup() {
    step "Step 2: 备份关键数据"

    BACKUP_DIR="/root/ip-sentinel-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    info "创建备份目录: ${BACKUP_DIR}"

    # 备份 Master
    if $HAS_MASTER && [ -d "/opt/ip_sentinel_master" ]; then
        cp -a /opt/ip_sentinel_master "${BACKUP_DIR}/ip_sentinel_master"
        info "已备份 Master (/opt/ip_sentinel_master)"
    fi

    # 备份 Agent
    if $HAS_AGENT && [ -d "/opt/ip_sentinel" ]; then
        cp -a /opt/ip_sentinel "${BACKUP_DIR}/ip_sentinel"
        info "已备份 Agent (/opt/ip_sentinel)"
    fi

    # 备份 systemd 服务文件
    if command -v systemctl > /dev/null 2>&1; then
        local svc_count=0
        while IFS= read -r -d '' svc; do
            cp -a "$svc" "${BACKUP_DIR}/" 2>/dev/null || true
            svc_count=$((svc_count + 1))
        done < <(find /etc/systemd/system/ -name 'ip-sentinel-*.service' -print0 2>/dev/null || true)
        while IFS= read -r -d '' tmr; do
            cp -a "$tmr" "${BACKUP_DIR}/" 2>/dev/null || true
        done < <(find /etc/systemd/system/ -name 'ip-sentinel-*.timer' -print0 2>/dev/null || true)
        if [ "$svc_count" -gt 0 ]; then
            info "已备份 ${svc_count} 个 systemd 服务文件"
        fi
    fi

    # 备份 crontab
    if crontab -l > "${BACKUP_DIR}/crontab.txt" 2>/dev/null; then
        info "已备份 crontab"
    else
        touch "${BACKUP_DIR}/crontab.txt"
    fi

    # 记录备份路径
    echo "$BACKUP_DIR" > /tmp/.ip_sentinel_backup_path

    echo ""
    info "备份完成: ${BACKUP_DIR}"
    ls -la "${BACKUP_DIR}/"
}

# ==========================================================
# 3. 确认升级
# ==========================================================
confirm_upgrade() {
    step "Step 3: 确认升级"

    echo ""
    echo "========================================"
    echo "  升级确认信息"
    echo "========================================"
    if $HAS_MASTER; then
        echo "  Master:     v${MASTER_VER} → v${MASTER_TARGET}"
    fi
    if $HAS_AGENT; then
        echo "  Agent:      v${AGENT_VER} → v${AGENT_TARGET}"
    fi
    if $HAS_MASTER && $HAS_AGENT; then
        echo "  升级顺序:   Master 优先 → Agent 随后"
    fi
    echo "  备份位置:   ${BACKUP_DIR}"
    echo "========================================"
    echo ""

    read -r -p "👉 是否继续升级？(y/n, 默认 y): " UPGRADE_CONFIRM
    if [[ "$UPGRADE_CONFIRM" =~ ^[Nn]$ ]]; then
        info "已取消升级。备份保留在: ${BACKUP_DIR}"
        exit 0
    fi

    info "升级确认，开始执行..."
}

# ==========================================================
# 4. 执行升级（Master 优先，Agent 随后）
# ==========================================================
upgrade_master() {
    step "Step 4a: 升级 Master"

    info "调用 Master 安装脚本 (SILENT_MASTER_OTA=true)..."
    export SILENT_MASTER_OTA="true"

    if ! bash -c "$(curl -fsSL "${REPO_RAW_URL}/master/install_master.sh?t=$(date +%s)")"; then
        error "Master 升级失败！"
        echo -e "💡 备份位于: ${BACKUP_DIR}"
        echo -e "💡 回滚: systemctl stop ip-sentinel-master.service 2>/dev/null || pkill -f tg_master.sh 2>/dev/null || true"
        echo -e "         rm -rf /opt/ip_sentinel_master"
        echo -e "         cp -a ${BACKUP_DIR}/ip_sentinel_master /opt/ip_sentinel_master"
        echo -e "         systemctl daemon-reload && systemctl restart ip-sentinel-master.service"
        return 1
    fi

    # Master 升级后等待服务就绪
    sleep 3
    info "Master 升级完成。"
    return 0
}

upgrade_agent() {
    step "Step 4b: 升级 Agent"

    info "调用 Agent 安装脚本 (SILENT_OTA=true)..."
    export SILENT_OTA="true"

    if ! bash -c "$(curl -fsSL "${REPO_RAW_URL}/install.sh?t=$(date +%s)")"; then
        error "Agent 升级失败！"
        echo -e "💡 备份位于: ${BACKUP_DIR}"
        echo -e "💡 回滚: systemctl stop ip-sentinel-agent-daemon.service 2>/dev/null || pkill -f agent_daemon.sh 2>/dev/null || true"
        echo -e "         rm -rf /opt/ip_sentinel"
        echo -e "         cp -a ${BACKUP_DIR}/ip_sentinel /opt/ip_sentinel"
        echo -e "         systemctl daemon-reload && systemctl restart ip-sentinel-agent-daemon.service"
        return 1
    fi

    # Agent 升级后等待服务就绪
    sleep 3
    info "Agent 升级完成。"
    return 0
}

# ==========================================================
# 5. 升级后验证
# ==========================================================
do_verify() {
    step "Step 5: 升级后验证"

    local errors=0
    local warns=0

    # -------- Master 验证 --------
    if $HAS_MASTER; then
        echo ""
        echo "--- Master 验证 ---"

        local new_ver
        new_ver=$(grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf 2>/dev/null | cut -d'"' -f2 || true)
        new_ver="${new_ver:-未知}"
        echo -e "📌 版本: ${new_ver}"

        if [ "$new_ver" = "未知" ]; then
            warn "Master 版本号读取失败"
            warns=$((warns + 1))
        elif [ "$new_ver" = "$MASTER_TARGET" ]; then
            info "Master 版本号匹配 (v${new_ver})"
        else
            warn "Master 版本不匹配: 期望 v${MASTER_TARGET}, 实际 v${new_ver}"
            warns=$((warns + 1))
        fi

        # HMAC_SECRET
        if grep -q "^HMAC_SECRET=" /opt/ip_sentinel_master/master.conf 2>/dev/null; then
            local hmac
            hmac=$(grep "^HMAC_SECRET=" /opt/ip_sentinel_master/master.conf | cut -d'"' -f2 || true)
            if [ -n "$hmac" ]; then
                info "Master HMAC_SECRET 已配置"
            fi
        else
            warn "Master HMAC_SECRET 未配置"
            warns=$((warns + 1))
        fi

        # 进程
        if pgrep -f "tg_master.sh" > /dev/null 2>&1; then
            info "Master 进程运行中"
        else
            warn "Master 进程未运行，尝试 systemctl restart..."
            warns=$((warns + 1))
            systemctl restart ip-sentinel-master.service 2>/dev/null || true
            sleep 2
        fi

        # 数据库
        if [ -f /opt/ip_sentinel_master/sentinel.db ]; then
            if command -v sqlite3 > /dev/null 2>&1; then
                local ncount
                ncount=$(sqlite3 /opt/ip_sentinel_master/sentinel.db "SELECT COUNT(*) FROM nodes;" 2>/dev/null || echo "?")
                info "数据库正常，节点数: ${ncount}"
            fi
        else
            warn "Master 数据库文件不存在"
            warns=$((warns + 1))
        fi

        # Systemd
        if command -v systemctl > /dev/null 2>&1; then
            if systemctl is-active ip-sentinel-master.service > /dev/null 2>&1; then
                info "Master systemd 服务运行中"
            else
                warn "Master systemd 服务未激活"
                errors=$((errors + 1))
            fi
        fi
    fi

    # -------- Agent 验证 --------
    if $HAS_AGENT; then
        echo ""
        echo "--- Agent 验证 ---"

        local new_ver
        new_ver=$(grep "^AGENT_VERSION=" /opt/ip_sentinel/config.conf 2>/dev/null | cut -d'"' -f2 || true)
        new_ver="${new_ver:-未知}"
        echo -e "📌 版本: ${new_ver}"

        if [ "$new_ver" = "未知" ]; then
            warn "Agent 版本号读取失败"
            warns=$((warns + 1))
        elif [ "$new_ver" = "$AGENT_TARGET" ]; then
            info "Agent 版本号匹配 (v${new_ver})"
        else
            warn "Agent 版本不匹配: 期望 v${AGENT_TARGET}, 实际 v${new_ver}"
            warns=$((warns + 1))
        fi

        # HMAC_SECRET
        if grep -q "^HMAC_SECRET=" /opt/ip_sentinel/config.conf 2>/dev/null; then
            local hmac
            hmac=$(grep "^HMAC_SECRET=" /opt/ip_sentinel/config.conf | cut -d'"' -f2 || true)
            if [ -n "$hmac" ]; then
                info "Agent HMAC_SECRET 已配置"
            fi
        else
            warn "Agent HMAC_SECRET 未配置"
            warns=$((warns + 1))
        fi

        # 进程
        if pgrep -f "webhook.py" > /dev/null 2>&1 || pgrep -f "agent_daemon.sh" > /dev/null 2>&1; then
            info "Agent 进程运行中"
        else
            warn "Agent 进程未运行"
            warns=$((warns + 1))
        fi

        # NODE_NAME 保留检查
        if [ -n "$OLD_NODE_NAME" ]; then
            local cur_name
            cur_name=$(grep "^NODE_NAME=" /opt/ip_sentinel/config.conf 2>/dev/null | cut -d'"' -f2 || true)
            if [ "$cur_name" = "$OLD_NODE_NAME" ]; then
                info "节点名称保持不变: ${cur_name}"
            else
                warn "节点名称从 ${OLD_NODE_NAME} 变更为 ${cur_name:-空}"
                warns=$((warns + 1))
            fi
        fi

        # core.bak 提示
        if [ -d /opt/ip_sentinel/core.bak ]; then
            info "core.bak 备份仍存在（可手动清理）"
        fi

        # Systemd
        if command -v systemctl > /dev/null 2>&1; then
            if systemctl is-active ip-sentinel-agent-daemon.service > /dev/null 2>&1; then
                info "Agent systemd 服务运行中"
            else
                warn "Agent systemd 服务未激活"
                errors=$((errors + 1))
            fi
        fi
    fi

    echo ""
    if [ "$errors" -eq 0 ] && [ "$warns" -eq 0 ]; then
        info "验证全部通过。"
    elif [ "$errors" -eq 0 ]; then
        warn "验证通过（${warns} 项警告）"
    else
        error "验证未通过（${errors} 项错误, ${warns} 项警告）"
    fi

    return "$errors"
}

# ==========================================================
# 6. 输出总结
# ==========================================================
print_summary() {
    local backup_path
    backup_path=$(cat /tmp/.ip_sentinel_backup_path 2>/dev/null || echo "${BACKUP_DIR:-未知}")

    echo ""
    echo "========================================"
    echo "  IP-Sentinel 升级报告"
    echo "========================================"
    if $HAS_MASTER; then
        echo "  Master:     v${MASTER_VER} → v${MASTER_TARGET}"
    fi
    if $HAS_AGENT; then
        echo "  Agent:      v${AGENT_VER} → v${AGENT_TARGET}"
    fi
    echo "  备份位置:   ${backup_path}"
    echo "========================================"
    echo ""
    echo -e "${GREEN}✅ 升级流程已执行完毕。${NC}"
    echo ""
    echo -e "💡 后续操作建议："
    echo -e "   1. 在 TG 中发送 /start 确认 Master 面板显示新版本"
    echo -e "   2. 发送 /nodes 查看节点列表及 Agent 版本号"
    if $HAS_AGENT; then
        echo -e "   3. 检查 HMAC_SECRET: grep 'HMAC_SECRET' /opt/ip_sentinel/config.conf"
    fi
    echo -e "   4. 确认无误后清理备份: rm -rf ${backup_path}"
    echo ""
    echo -e "📦 备份保留在: ${backup_path}"
    echo -e "   如需回滚，可手动从备份恢复。"
}

# ==========================================================
# 主流程
# ==========================================================
main() {
    echo ""
    echo "========================================"
    echo "  IP-Sentinel 一键备份升级脚本"
    echo "  hardened 分支"
    echo "========================================"
    echo ""

    check_root
    check_network
    check_commands
    detect_roles

    do_backup

    confirm_upgrade

    local upgrade_ok=true
    local verify_errors=0

    # 升级顺序: Master 优先 → Agent 随后
    if $HAS_MASTER; then
        if ! upgrade_master; then
            upgrade_ok=false
        fi
    fi

    if $HAS_AGENT && $upgrade_ok; then
        if ! upgrade_agent; then
            upgrade_ok=false
        fi
    fi

    if $upgrade_ok; then
        do_verify || verify_errors=$?
        print_summary

        if [ "$verify_errors" -gt 0 ]; then
            echo ""
            warn "验证发现 ${verify_errors} 项异常，建议检查日志。"
        fi
    else
        echo ""
        error "升级执行阶段失败。"
        echo -e "💡 备份位于: ${BACKUP_DIR}"
        echo -e "💡 请根据上面的回滚提示手动恢复。"
        exit 1
    fi
}

main "$@"
