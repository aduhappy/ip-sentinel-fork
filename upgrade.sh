#!/bin/bash
# ==========================================================
# IP-Sentinel 一键备份升级脚本 — hardened 分支
# 用法: bash <(curl -fsSL https://raw.githubusercontent.com/aduhappy/ip-sentinel-fork/hardened/upgrade.sh)
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
ROLE=""
INSTALL_DIR=""
CONF_FILE=""
SERVICE_NAME=""
CURRENT_VERSION=""
TARGET_VERSION=""
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

detect_role() {
    step "Step 1: 环境检测"

    if [ -f "/opt/ip_sentinel_master/master.conf" ]; then
        ROLE="master"
        INSTALL_DIR="/opt/ip_sentinel_master"
        CONF_FILE="${INSTALL_DIR}/master.conf"
        SERVICE_NAME="ip-sentinel-master.service"

        CURRENT_VERSION=$(grep "^MASTER_VERSION=" "$CONF_FILE" 2>/dev/null | cut -d'"' -f2 || true)
        CURRENT_VERSION="${CURRENT_VERSION:-未知}"

        info "检测到 Master 角色 (v${CURRENT_VERSION})"

    elif [ -f "/opt/ip_sentinel/config.conf" ]; then
        ROLE="agent"
        INSTALL_DIR="/opt/ip_sentinel"
        CONF_FILE="${INSTALL_DIR}/config.conf"
        SERVICE_NAME="ip-sentinel-agent-daemon.service"

        CURRENT_VERSION=$(grep "^AGENT_VERSION=" "$CONF_FILE" 2>/dev/null | cut -d'"' -f2 || true)
        OLD_NODE_NAME=$(grep "^NODE_NAME=" "$CONF_FILE" 2>/dev/null | cut -d'"' -f2 || true)
        CURRENT_VERSION="${CURRENT_VERSION:-未知}"

        info "检测到 Agent 角色 (v${CURRENT_VERSION})"
    else
        error "未检测到已安装的 IP-Sentinel（Master 或 Agent）。"
        echo -e "💡 请确认以下路径之一存在："
        echo -e "   - /opt/ip_sentinel_master/master.conf (Master)"
        echo -e "   - /opt/ip_sentinel/config.conf (Agent)"
        exit 1
    fi

    # 获取目标版本
    local version_line
    if [ "$ROLE" = "master" ]; then
        version_line=$(curl -sfL "${REPO_RAW_URL}/version.txt?t=$(date +%s)" | grep "^MASTER_VERSION=" || true)
        TARGET_VERSION=$(echo "$version_line" | cut -d'=' -f2 | tr -d '[:space:]')
    else
        version_line=$(curl -sfL "${REPO_RAW_URL}/version.txt?t=$(date +%s)" | grep "^AGENT_VERSION=" || true)
        TARGET_VERSION=$(echo "$version_line" | cut -d'=' -f2 | tr -d '[:space:]')
    fi
    TARGET_VERSION="${TARGET_VERSION:-未知}"

    info "当前版本: v${CURRENT_VERSION}"
    info "目标版本: v${TARGET_VERSION}"

    # 版本比较
    if [ "$CURRENT_VERSION" != "未知" ] && [ "$TARGET_VERSION" != "未知" ]; then
        if ! version_lt "$CURRENT_VERSION" "$TARGET_VERSION"; then
            warn "当前版本 (v${CURRENT_VERSION}) 已达到或超过目标版本 (v${TARGET_VERSION})。"
            echo -e "   是否仍要强制重新部署？(y/n, 默认 n): "
            read -r FORCE_CHOICE
            if [[ ! "$FORCE_CHOICE" =~ ^[Yy]$ ]]; then
                info "已取消升级。"
                exit 0
            fi
            warn "强制重新部署已确认，将继续执行..."
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

    if [ "$ROLE" = "master" ]; then
        if [ -d "/opt/ip_sentinel_master" ]; then
            cp -a /opt/ip_sentinel_master "${BACKUP_DIR}/ip_sentinel_master"
            info "已备份 Master 目录 (/opt/ip_sentinel_master)"
        fi
    else
        if [ -d "/opt/ip_sentinel" ]; then
            cp -a /opt/ip_sentinel "${BACKUP_DIR}/ip_sentinel"
            info "已备份 Agent 目录 (/opt/ip_sentinel)"
        fi
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
        else
            warn "未找到 IP-Sentinel systemd 服务文件"
        fi
    fi

    # 备份 crontab
    if crontab -l > "${BACKUP_DIR}/crontab.txt" 2>/dev/null; then
        info "已备份 crontab"
    else
        warn "无 crontab 或无法读取 (非 root 或 crontab 为空)"
        touch "${BACKUP_DIR}/crontab.txt"
    fi

    # 记录备份路径供后续使用
    echo "$BACKUP_DIR" > /tmp/.ip_sentinel_backup_path

    echo ""
    info "备份完成: ${BACKUP_DIR}"
    echo -e "   备份内容:"
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
    echo "  角色:           ${ROLE}"
    echo "  当前版本:       v${CURRENT_VERSION}"
    echo "  目标版本:       v${TARGET_VERSION}"
    echo "  安装目录:       ${INSTALL_DIR}"
    echo "  备份位置:       ${BACKUP_DIR}"
    echo "========================================"
    echo ""

    read -r -p "👉 是否继续升级？(y/n, 默认 y): " UPGRADE_CONFIRM
    if [[ "$UPGRADE_CONFIRM" =~ ^[Nn]$ ]]; then
        info "已取消升级。备份保留在: ${BACKUP_DIR}"
        echo -e "💡 如需手动清理备份: rm -rf ${BACKUP_DIR}"
        exit 0
    fi

    info "升级确认，开始执行..."
}

# ==========================================================
# 4. 执行升级
# ==========================================================
do_upgrade() {
    step "Step 4: 执行升级"

    echo "🚀 正在升级 ${ROLE} (v${CURRENT_VERSION} → v${TARGET_VERSION})..."
    echo ""

    local UPGRADE_EXIT=0

    if [ "$ROLE" = "master" ]; then
        info "调用 Master 安装脚本 (SILENT_MASTER_OTA=true)..."
        export SILENT_MASTER_OTA="true"
        bash -c "$(curl -fsSL "${REPO_RAW_URL}/master/install_master.sh?t=$(date +%s)")" || UPGRADE_EXIT=$?
    else
        info "调用 Agent 安装脚本 (SILENT_OTA=true)..."
        export SILENT_OTA="true"
        bash -c "$(curl -fsSL "${REPO_RAW_URL}/install.sh?t=$(date +%s)")" || UPGRADE_EXIT=$?
    fi

    echo ""
    if [ "$UPGRADE_EXIT" -ne 0 ]; then
        error "升级脚本执行失败 (exit code: ${UPGRADE_EXIT})。"
        echo -e "💡 备份位于: ${BACKUP_DIR}"
        echo -e ""
        echo -e "💡 回滚命令参考:"
        if [ "$ROLE" = "master" ]; then
            echo -e "   systemctl stop ${SERVICE_NAME} 2>/dev/null || pkill -f tg_master.sh 2>/dev/null || true"
            echo -e "   rm -rf /opt/ip_sentinel_master"
            echo -e "   cp -a ${BACKUP_DIR}/ip_sentinel_master /opt/ip_sentinel_master"
            echo -e "   systemctl daemon-reload && systemctl restart ${SERVICE_NAME}"
        else
            echo -e "   systemctl stop ${SERVICE_NAME} 2>/dev/null || pkill -f agent_daemon.sh 2>/dev/null || true"
            echo -e "   rm -rf /opt/ip_sentinel"
            echo -e "   cp -a ${BACKUP_DIR}/ip_sentinel /opt/ip_sentinel"
            echo -e "   systemctl daemon-reload && systemctl restart ${SERVICE_NAME}"
        fi
        return 1
    fi

    info "升级脚本执行完毕。"
    return 0
}

# ==========================================================
# 5. 升级后验证
# ==========================================================
do_verify() {
    step "Step 5: 升级后验证"

    local errors=0
    local warns=0

    # --- 版本检查 ---
    local new_ver=""
    if [ "$ROLE" = "master" ]; then
        new_ver=$(grep "^MASTER_VERSION=" /opt/ip_sentinel_master/master.conf 2>/dev/null | cut -d'"' -f2 || true)
        new_ver="${new_ver:-未知}"
        echo -e "📌 Master 版本: ${new_ver}"
    else
        new_ver=$(grep "^AGENT_VERSION=" /opt/ip_sentinel/config.conf 2>/dev/null | cut -d'"' -f2 || true)
        new_ver="${new_ver:-未知}"
        echo -e "📌 Agent 版本: ${new_ver}"
    fi

    if [ "$new_ver" = "未知" ]; then
        warn "版本号读取失败，配置文件可能异常。"
        warns=$((warns + 1))
    elif [ "$new_ver" = "$TARGET_VERSION" ]; then
        info "版本号匹配 (v${new_ver})"
    else
        warn "版本号不匹配: 期望 v${TARGET_VERSION}, 实际 v${new_ver}"
        warns=$((warns + 1))
    fi

    # --- HMAC_SECRET 检查 ---
    if [ -f "$CONF_FILE" ] && grep -q "^HMAC_SECRET=" "$CONF_FILE" 2>/dev/null; then
        local hmac_val
        hmac_val=$(grep "^HMAC_SECRET=" "$CONF_FILE" | cut -d'"' -f2 || true)
        if [ -n "$hmac_val" ]; then
            info "HMAC_SECRET 已配置 (长度: ${#hmac_val})"
        else
            warn "HMAC_SECRET 为空值"
            warns=$((warns + 1))
        fi
    else
        warn "HMAC_SECRET 未配置（双轨兼容会使用 CHAT_ID）"
        warns=$((warns + 1))
    fi

    # --- 进程检查 ---
    if [ "$ROLE" = "master" ]; then
        if pgrep -f "tg_master.sh" > /dev/null 2>&1; then
            info "Master 进程 (tg_master.sh) 运行中"
        else
            warn "Master 进程未运行，尝试启动..."
            warns=$((warns + 1))
            if command -v systemctl > /dev/null 2>&1; then
                systemctl restart "${SERVICE_NAME}" 2>/dev/null || true
                sleep 1
                if pgrep -f "tg_master.sh" > /dev/null 2>&1; then
                    info "Master 进程已通过 systemd 启动"
                    warns=$((warns - 1))
                fi
            fi
        fi
    else
        local agent_alive=false
        if pgrep -f "webhook.py" > /dev/null 2>&1 || pgrep -f "agent_daemon.sh" > /dev/null 2>&1; then
            info "Agent 进程运行中"
            agent_alive=true
        else
            warn "Agent 进程未运行"
            warns=$((warns + 1))
        fi

        # 旧版 core.bak 备份残留提示
        if [ -d /opt/ip_sentinel/core.bak ]; then
            info "core.bak 备份仍存在（新引擎已通过验证但未清理）"
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
    fi

    # --- 数据库检查 (Master) ---
    if [ "$ROLE" = "master" ]; then
        if [ -f /opt/ip_sentinel_master/sentinel.db ]; then
            local node_count=0
            if command -v sqlite3 > /dev/null 2>&1; then
                node_count=$(sqlite3 /opt/ip_sentinel_master/sentinel.db "SELECT COUNT(*) FROM nodes;" 2>/dev/null || echo "0")
                info "数据库正常，节点数: ${node_count}"
            else
                warn "sqlite3 不可用，跳过数据库完整性检查"
            fi
        else
            warn "数据库文件 sentinel.db 不存在"
            warns=$((warns + 1))
        fi
    fi

    # --- Systemd 服务检查 ---
    if command -v systemctl > /dev/null 2>&1; then
        if systemctl is-active "$SERVICE_NAME" > /dev/null 2>&1; then
            info "Systemd 服务运行中 (${SERVICE_NAME})"
        else
            warn "Systemd 服务未激活 (${SERVICE_NAME})"
            errors=$((errors + 1))
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
    echo "  角色:         ${ROLE}"
    echo "  旧版本:       ${CURRENT_VERSION:-未知}"
    echo "  新版本:       ${TARGET_VERSION:-未知}"
    echo "  备份位置:     ${backup_path}"
    echo "========================================"

    echo ""
    echo -e "${GREEN}✅ 升级流程已执行完毕。${NC}"
    echo -e ""
    echo -e "💡 后续操作建议："
    echo -e "   1. 检查 TG Master 面板 /start 确认功能正常"
    if [ "$ROLE" = "master" ]; then
        echo -e "   2. 在 TG 中发送 /nodes 查看各 Agent 版本号"
        echo -e "   3. 验证 HMAC 鉴权: curl -s 'https://<YOUR_IP>:<PORT>/trigger_ota?t=\$(date +%s)&sign=FAKE'"
        echo -e "   4. 确认各 Agent 已升级后，手动清理备份: rm -rf ${backup_path}"
    else
        echo -e "   2. 检查 HMAC_SECRET: grep '^HMAC_SECRET=' /opt/ip_sentinel/config.conf"
        echo -e "   3. 检查升级日志: cat /opt/ip_sentinel/logs/ota_upgrade.log 2>/dev/null"
        echo -e "   4. 确认 Master 端节点在线后，清理备份: rm -rf ${backup_path}"
    fi
    echo -e ""
    echo -e "📦 备份保留在: ${backup_path}"
    echo -e "   如需回滚，参考上述手动回滚命令。"
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
    detect_role

    do_backup

    confirm_upgrade

    if do_upgrade; then
        local verify_errors=0
        do_verify || verify_errors=$?
        print_summary
        if [ "$verify_errors" -gt 0 ]; then
            echo ""
            warn "验证发现 ${verify_errors} 项错误，建议检查日志或手动回滚。"
        fi
    else
        echo ""
        error "升级执行阶段失败。"
        echo -e "💡 备份位于: $(cat /tmp/.ip_sentinel_backup_path 2>/dev/null || echo '未知')"
        echo -e "💡 请按照上方提示手动回滚。"
        exit 1
    fi
}

main "$@"
