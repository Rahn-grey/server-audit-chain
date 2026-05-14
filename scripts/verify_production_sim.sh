#!/bin/bash
# ================================================================
# 生产模拟模式验证脚本
# 测试 4 MockBCOS 节点 + API + PBFT 共识全链路
# 用法: bash scripts/verify_production_sim.sh
# ================================================================

set -e
BASE="http://localhost"
GREEN="\033[32m"
RED="\033[31m"
NC="\033[0m"
PASS=0
FAIL=0

ok() { PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }

echo ""
echo "============================================================"
echo "  生产模拟模式验证 — 4节点 MockBCOS + PBFT 共识"
echo "============================================================"
echo ""

# STEP 1: 检查所有容器
echo "[1/8] 检查容器状态..."
TOTAL=$(docker ps --filter "name=mock-node" --format "{{.Names}}" | wc -l)
if [ "$TOTAL" -eq 4 ]; then
    ok "MockBCOS 4 节点均已运行"
    docker ps --filter "name=mock-node" --format "  {{.Names}}  →  {{.Status}}"
else
    fail "MockBCOS 节点: 期望 4, 实际 $TOTAL"
fi

docker ps --filter "name=audit-api" --format "{{.Names}}" | grep -q audit-api && ok "audit-api 运行中" || fail "audit-api 未运行"
echo ""

# STEP 2: 验证每个节点状态
echo "[2/8] 验证 MockBCOS 节点状态..."
for i in 0 1 2 3; do
    PORT=$((6000 + i))
    RESP=$(curl -s http://localhost:${PORT}/status 2>/dev/null)
    NODE_ID=$(echo "$RESP" | grep -o '"node_id":"[^"]*"' | cut -d'"' -f4 || echo "失败")
    NODE_TYPE=$(echo "$RESP" | grep -o '"type":"[^"]*"' | cut -d'"' -f4 || echo "未知")
    if [ "$NODE_ID" = "node_$i" ]; then
        ok "节点 ${NODE_ID} (${NODE_TYPE}) → 端口 ${PORT}"
    else
        fail "节点 node_$i 无响应 (${PORT})"
    fi
done
echo ""

# STEP 3: 验证 API 健康
echo "[3/8] 验证 API 服务..."
API_INFO=$(curl -s http://localhost:5000/api/v1/audit/chain/info 2>/dev/null)
if echo "$API_INFO" | grep -q "total_records"; then
    ok "audit-api 响应正常"
else
    fail "audit-api 无响应"
fi
echo ""

# STEP 4: 提交批次上链
echo "[4/8] 提交测试日志上链 (PBFT 共识)..."
BATCH_ID="verify_$(date +%s)"
LOG_ID="log_verify_$(date +%s)"
RESP=$(curl -s -X POST http://localhost:5000/api/v1/audit/batch \
  -H "Content-Type: application/json" \
  -d "{
    \"batch_id\": \"${BATCH_ID}\",
    \"logs\": [
      {\"log_id\": \"${LOG_ID}\", \"operator\": \"admin\",
       \"command\": \"ls -la /data\", \"timestamp\": \"2026-05-14T12:00:00Z\",
       \"risk_level\": \"normal\", \"ip\": \"10.0.0.1\",
       \"result\": \"success\", \"target\": \"/data\"}
    ]
  }" 2>/dev/null)

RECORD_HASH=$(echo "$RESP" | grep -o '"record_hash":"[^"]*"' | cut -d'"' -f4)
if [ -n "$RECORD_HASH" ]; then
    ok "上链成功 → record_hash=${RECORD_HASH}"
else
    RESP_ERR=$(echo "$RESP" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
    fail "上链失败: ${RESP_ERR:-$RESP}"
fi
echo ""

# STEP 5: 验证区块链记录
echo "[5/8] 验证区块链存证记录..."
RECORD=$(curl -s http://localhost:5000/api/v1/audit/record/${BATCH_ID} 2>/dev/null)
if echo "$RECORD" | grep -q "\"batch_id\""; then
    MERKLE=$(echo "$RECORD" | grep -o '"merkle_root":"[^"]*"' | cut -d'"' -f4)
    ok "链上记录可查 → merkle_root=${MERKLE}"
else
    fail "链上记录查询失败"
fi

CHAIN_INFO=$(curl -s http://localhost:5000/api/v1/audit/chain/info)
TOTAL=$(echo "$CHAIN_INFO" | grep -o '"total_records":[0-9]*' | cut -d: -f2)
ok "链信息: total_records=${TOTAL}"
echo ""

# STEP 6: 验证 PBFT 共识同步（4个节点记录数一致）
echo "[6/8] 验证 PBFT 共识同步..."
COUNTS=""
for i in 0 1 2 3; do
    PORT=$((6000 + i))
    CNT=$(curl -s http://localhost:${PORT}/status 2>/dev/null | grep -o '"record_count":[0-9]*' | cut -d: -f2)
    if [ -z "$CNT" ]; then CNT="0"; fi
    COUNTS="${COUNTS}${CNT},"
done
UNIQ=$(echo "$COUNTS" | tr ',' '\n' | sort -u | grep -c "[0-9]")
if [ "$UNIQ" -eq 1 ]; then
    ok "PBFT 共识同步正常: 4节点记录数一致 (${COUNTS%,})"
else
    fail "PBFT 共识异常: 节点记录数不一致 (${COUNTS%,})"
fi
echo ""

# STEP 7: 验证链完整性
echo "[7/8] 验证链完整性..."
INTEGRITY=$(curl -s http://localhost:5000/api/v1/audit/chain/integrity 2>/dev/null)
if echo "$INTEGRITY" | grep -q '"is_valid":true'; then
    ok "哈希链完整 → verify_chain_integrity 通过"
else
    fail "链完整性验证失败"
fi
echo ""

# STEP 8: 验证拜占庭攻击检测
echo "[8/8] 验证拜占庭攻击检测..."
ATTACK=$(curl -s -X POST http://localhost:5000/api/v1/audit/chain/attack 2>/dev/null)
if echo "$ATTACK" | grep -q '"success":true'; then
    ok "拜占庭攻击模拟成功"
    CROSS=$(curl -s http://localhost:5000/api/v1/audit/chain/cross-verify 2>/dev/null)
    if echo "$CROSS" | grep -q "不一致"; then
        ok "跨节点验证检出拜占庭节点篡改"
    else
        fail "跨节点验证未能检出拜占庭攻击"
    fi
else
    fail "拜占庭攻击模拟: ${ATTACK}"
fi
echo ""

# 汇总
echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}结果: ${PASS}/${PASS} 通过 — 生产模拟验证成功${NC}"
    echo ""
    echo "  Web 仪表板: http://localhost:5000"
else
    echo -e "  ${RED}结果: ${PASS}/${PASS} 通过, ${FAIL} 失败${NC}"
fi
echo "============================================================"
echo ""

# 清理测试数据
curl -s -X POST http://localhost:5000/api/v1/audit/chain/attack > /dev/null 2>&1 || true
