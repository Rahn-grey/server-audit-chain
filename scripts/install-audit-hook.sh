#!/bin/bash
# ====================================================================
# 服务器操作审计 Hook — 安装脚本
# ====================================================================
# 安装到 /etc/profile.d/ 后，所有用户的 bash 命令都会被自动记录。
#
# 安装:   sudo bash install-audit-hook.sh
# 卸载:   sudo bash install-audit-hook.sh --uninstall
# 测试:   bash -c 'ls -la' 然后 tail -f /var/log/audit/commands.log
#
# 原理:
#   - bash DEBUG trap: 每条命令执行前触发，捕获命令文本
#   - 命令执行后记录进程返回码，判断 success/failed
#   - 写入格式: TIMESTAMP|USER|IP|COMMAND|RESULT
#   - 采集器 watcher.py 实时 tail 该文件，解析后上链
# ====================================================================

set -e

HOOK_SCRIPT="/etc/profile.d/audit-hook.sh"
LOG_DIR="/var/log/audit"
LOG_FILE="$LOG_DIR/commands.log"
DATA_FILE="$LOG_DIR/.audit_data"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ "$1" = "--uninstall" ]; then
    if [ -f "$HOOK_SCRIPT" ]; then
        rm -f "$HOOK_SCRIPT" "$DATA_FILE"
        echo -e "${GREEN}[✓] 审计 Hook 已卸载${NC}"
        echo "  已删除: $HOOK_SCRIPT"
        echo "  日志文件保留: $LOG_FILE"
    else
        echo -e "${RED}[✗] 审计 Hook 未安装${NC}"
    fi
    exit 0
fi

# ------------------------------------------------------------------
# 安装
# ------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[✗] 需要 root 权限安装${NC}"
    echo "  请使用: sudo bash $0"
    exit 1
fi

# 创建日志目录
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 755 "$LOG_DIR"
chmod 644 "$LOG_FILE"

# 获取本机名作为 IP 标识
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")

# 写入 Hook 脚本
cat > "$HOOK_SCRIPT" << 'HOOKEOF'
# ===== 服务器操作审计 Hook =====
# 安装位置: /etc/profile.d/audit-hook.sh
# 采集器监听: /var/log/audit/commands.log

export AUDIT_LOG_FILE="/var/log/audit/commands.log"

# --- bash: 使用 DEBUG trap ---
if [ -n "$BASH_VERSION" ]; then
    # 避免在子 shell 中重复安装
    if [ -z "$_AUDIT_HOOK_LOADED" ]; then
        export _AUDIT_HOOK_LOADED=1

        _audit_last_cmd=""

        # DEBUG trap: 命令执行前触发
        _audit_trap_debug() {
            local cmd
            cmd=$(history 1 2>/dev/null | sed 's/^[ ]*[0-9]*[ ]*//')
            if [ -n "$cmd" ] && [ "$cmd" != "$_audit_last_cmd" ]; then
                _audit_last_cmd="$cmd"
                _audit_cmd_start=$(date +%s 2>/dev/null || echo 0)
            fi
        }

        # PROMPT_COMMAND: 命令执行后触发
        _audit_trap_post() {
            local rc=$?
            local cmd="$_audit_last_cmd"
            local ip
            ip=$(echo "$SSH_CLIENT" | awk '{print $1}' 2>/dev/null)
            [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
            [ -z "$ip" ] && ip="127.0.0.1"

            if [ -n "$cmd" ] && [ "$cmd" != "$_audit_last_written" ]; then
                _audit_last_written="$cmd"

                # 跳过审计 Hook 自身的命令、空命令、cd
                case "$cmd" in
                    _audit_*|"") return ;;
                esac

                local result="success"
                [ "$rc" -ne 0 ] && result="failed"

                local ts
                ts=$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z 2>/dev/null || date -Iseconds)
                echo "${ts}|${USER}|${ip}|${cmd}|${result}" >> "$AUDIT_LOG_FILE" 2>/dev/null
            fi
        }

        trap _audit_trap_debug DEBUG
        PROMPT_COMMAND="_audit_trap_post;${PROMPT_COMMAND}"
    fi
# --- sh: 使用 ENV 注入（sh 无 DEBUG trap，用 shell 包装器）---
elif [ -n "$_AUDIT_SH_WRAPPER" ] || [ "${0##*/}" = "sh" ] || [ "${0##*/}" = "bash" ]; then
    # 对纯 sh 用户，将 shell 替换为记录包装器
    # 设置 ENV 环境变量指向本脚本
    export ENV="$0"
fi
HOOKEOF

chmod 644 "$HOOK_SCRIPT"

# 写入采集器状态文件
cat > "$DATA_FILE" << DATAEOF
# 审计 Hook 元数据
installed_at=$(date -Iseconds)
hostname=${HOSTNAME}
log_file=${LOG_FILE}
DATAEOF

echo ""
echo -e "${GREEN}========================================="
echo "  服务器操作审计 Hook 安装完成"
echo -e "=========================================${NC}"
echo ""
echo "  日志文件:      $LOG_FILE"
echo "  Hook 脚本:     $HOOK_SCRIPT"
echo ""
echo "  生效方式:"
echo "    新登录的 bash shell → 自动生效"
echo "    当前 shell       → source /etc/profile.d/audit-hook.sh"
echo ""
echo "  验证:"
echo "    tail -f $LOG_FILE"
echo "    然后新开一个 bash 终端敲几条命令"
echo ""
echo "  卸载:"
echo "    sudo bash $0 --uninstall"
echo ""
echo "  配合采集器:"
echo "    python -m src.collector.agent --mode direct --log-file $LOG_FILE"
echo ""
