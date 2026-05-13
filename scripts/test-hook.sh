#!/bin/bash
# ====================================================================
# 验证审计 Hook 是否正常工作
# ====================================================================
# 模拟安装后的效果 — 直接往日志文件写入测试命令
# 然后验证采集器能否正确解析
# ====================================================================

LOG_FILE="${AUDIT_LOG_FILE:-/var/log/audit/commands.log}"

echo "=== 审计 Hook 功能验证 ==="
echo ""

# 测试1: 模拟写入几条不同风险等级的命令
echo "[1/4] 写入测试日志..."

# 确保目录存在
mkdir -p "$(dirname "$LOG_FILE")"

# 高危命令
echo "$(date -Iseconds)|root|192.168.1.10|rm -rf /data/temp/*|success" >> "$LOG_FILE"
echo "$(date -Iseconds)|zhangsan|10.0.0.5|dd if=/dev/zero of=/tmp/test bs=1M count=1024|failed" >> "$LOG_FILE"
echo "$(date -Iseconds)|attacker|10.0.0.99|chmod 777 /etc/shadow|success" >> "$LOG_FILE"

# 中危命令
echo "$(date -Iseconds)|deployer|172.16.0.1|systemctl restart nginx|success" >> "$LOG_FILE"
echo "$(date -Iseconds)|admin|172.16.0.2|useradd -m -s /bin/bash newuser|success" >> "$LOG_FILE"

# 常规命令
echo "$(date -Iseconds)|zhangsan|192.168.1.10|ls -la /var/log/|success" >> "$LOG_FILE"
echo "$(date -Iseconds)|lisi|192.168.1.11|cat /var/log/nginx/access.log|success" >> "$LOG_FILE"
echo "$(date -Iseconds)|zhangsan|192.168.1.10|df -h|success" >> "$LOG_FILE"
echo "$(date -Iseconds)|wangwu|192.168.1.12|grep ERROR /var/log/app/*.log|success" >> "$LOG_FILE"
echo "$(date -Iseconds)|lisi|192.168.1.11|who|success" >> "$LOG_FILE"

echo ""
echo "[2/4] 日志文件内容:"
echo "  文件: $LOG_FILE"
echo "  行数: $(wc -l < "$LOG_FILE")"
echo ""

echo "[3/4] 最新 5 条记录:"
tail -5 "$LOG_FILE" | while read line; do
    echo "  $line"
done

echo ""
echo "[4/4] 验证采集器解析..."
echo "  如果 Python 环境可用，将打印解析结果..."

# 尝试用 Python 解析
if command -v python3 &>/dev/null; then
    cd "$(dirname "$0")/.."
    python3 -c "
import sys
sys.path.insert(0, '.')
from src.collector.parser import parse_raw

with open('$LOG_FILE') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        r = parse_raw(line)
        if r:
            print(f\"  [{r['risk_level']:7s}] {r['operator']:10s} @ {r['ip']:14s} | {r['command'][:50]}\")
"
elif command -v python &>/dev/null; then
    cd "$(dirname "$0")/.."
    python -c "
import sys
sys.path.insert(0, '.')
from src.collector.parser import parse_raw
with open('$LOG_FILE') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        r = parse_raw(line)
        if r:
            print(f\"  [{r['risk_level']:7s}] {r['operator']:10s} @ {r['ip']:14s} | {r['command'][:50]}\")
"
else
    echo "  (Python 不可用，跳过解析验证)"
fi

echo ""
echo "=== 验证完成 ==="
echo ""
echo "下一步: 启动采集器将这些数据上链"
echo "  python -m src.collector.agent --mode direct --log-file $LOG_FILE"
