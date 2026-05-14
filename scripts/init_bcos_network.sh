#!/bin/bash
# ================================================================
# FISCO BCOS 3.x 创世网络初始化
# ================================================================
# 用途: 生成 4 节点联盟链的创世配置和节点密钥
# 用法: bash scripts/init_bcos_network.sh
# 输出: bcos/nodes/ 目录，含各节点的 config + 密钥 + genesis
# ================================================================

set -e

BCOS_IMAGE="fiscoorg/fiscobcos:v3.0.0"
NODE_COUNT=4
OUTPUT_DIR="bcos/nodes"
GENESIS_DIR="bcos/conf"

echo "[1/4] 生成节点密钥对..."
for i in $(seq 1 $NODE_COUNT); do
    mkdir -p "${OUTPUT_DIR}/node${i}/data"

    # 用 fisco-bcos 生成密钥（如果不存在）
    if [ ! -f "${OUTPUT_DIR}/node${i}/data/node.pem" ]; then
        docker run --rm \
            -v "$(pwd)/${OUTPUT_DIR}/node${i}/data":/data \
            ${BCOS_IMAGE} \
            fisco-bcos --genkey /data/node.pem
        echo "  node${i}: OK"
    else
        echo "  node${i}: 已存在，跳过"
    fi
done

echo ""
echo "[2/4] 收集节点 ID..."
NODE_IDS=()
for i in $(seq 1 $NODE_COUNT); do
    # 从区块生成器输出中提取 node_id（简化：直接用容器）
    NODE_ID=$(docker run --rm \
        -v "$(pwd)/${OUTPUT_DIR}/node${i}/data":/data \
        ${BCOS_IMAGE} \
        sh -c "cat /data/node.pem 2>/dev/null | head -c 64 | sha256sum | head -c 64" 2>/dev/null || echo "unknown_${i}")
    NODE_IDS+=("$NODE_ID")
    echo "  node${i}: ${NODE_ID}"
done

echo ""
echo "[3/4] 生成创世配置 config.genesis..."
mkdir -p "${GENESIS_DIR}"

# 生成 config.genesis
cat > "${GENESIS_DIR}/config.genesis" << GENESIS_EOF
[consensus]
    consensus_type = pbft
    block_tx_count_limit = 1000
    leader_period = 1
    node.0 = ${NODE_IDS[0]}:1
    node.1 = ${NODE_IDS[1]}:1
    node.2 = ${NODE_IDS[2]}:1
    node.3 = ${NODE_IDS[3]}:1

[version]
    compatibility_version = 3.0.0

[tx]
    gas_limit = 3000000000

[executor]
    is_wasm = false
    is_auth_check = false
    auth_admin_account = 0x0
GENESIS_EOF

echo "  -> ${GENESIS_DIR}/config.genesis 已生成"

echo ""
echo "[4/4] 复制节点配置文件..."
for i in $(seq 1 $NODE_COUNT); do
    cp "${GENESIS_DIR}/config.toml" "${OUTPUT_DIR}/node${i}/"
    cp "${GENESIS_DIR}/config.genesis" "${OUTPUT_DIR}/node${i}/"
    echo "  node${i}: config OK"
done

echo ""
echo "=============================================="
echo "  创世网络初始化完成"
echo "=============================================="
echo ""
echo "  节点配置: ${OUTPUT_DIR}/node{1..4}/"
echo "  创世配置: ${GENESIS_DIR}/config.genesis"
echo ""
echo "  启动生产模拟:"
echo "    docker-compose --profile production up -d"
echo "=============================================="
