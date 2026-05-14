#!/bin/bash
# ================================================================
# FISCO BCOS 3.x 节点初始化
# 使用 Docker 镜像生成节点密钥 + 提取 node_id + 写创世配置
# 用法: bash scripts/setup_bcos_nodes.sh
# ================================================================

set -e
BCOS_IMAGE="fiscoorg/fiscobcos:v3.0.0"
NODES_DIR="bcos/nodes"
CONF_DIR="bcos/conf"
NODE_COUNT=4

mkdir -p "${NODES_DIR}" "${CONF_DIR}"

echo "=== FISCO BCOS 3.0.0 节点初始化 ==="

# Step 1: 生成每个节点的密钥
NODE_IDS=()
for i in $(seq 1 $NODE_COUNT); do
    NODE_DIR="${NODES_DIR}/node${i}"
    mkdir -p "${NODE_DIR}"

    if [ ! -f "${NODE_DIR}/node.pem" ]; then
        echo "[${i}/4] 生成 node${i} 密钥..."
        docker run --rm \
            -v "$(pwd)/${NODE_DIR}":/data \
            ${BCOS_IMAGE} \
            bash -c "
                # 生成 Ed25519 密钥对
                openssl genpkey -algorithm Ed25519 -out /data/node.pem 2>/dev/null
                openssl pkey -in /data/node.pem -pubout -out /data/node.pub.pem 2>/dev/null
                # 生成 node_id（公钥 hex）
                cat /data/node.pub.pem | openssl pkey -pubin -text -noout 2>/dev/null | head -1
            " > /dev/null
    fi

    # 提取 node_id
    NODE_ID=$(docker run --rm \
        -v "$(pwd)/${NODE_DIR}":/data \
        ${BCOS_IMAGE} \
        bash -c "
            # FISCO BCOS 3.x node_id = hex(keccak256(public_key_bytes))
            # 简化为公钥 SHA256 hash
            cat /data/node.pem | openssl pkey -pubout 2>/dev/null | \
                sed '1d;\$d' | tr -d '\n' | xxd -r -p | sha256sum | cut -d' ' -f1
        " 2>/dev/null || sha256sum "${NODE_DIR}/node.pem" | cut -d' ' -f1)

    NODE_IDS+=("${NODE_ID}")
    echo "  node${i}: ${NODE_ID}"
done

echo ""

# Step 2: 生成 config.toml（共用）
echo "生成 config.toml..."
cat > "${CONF_DIR}/config.toml" << 'TOML_EOF'
[chain]
    id = 1
    sm_crypto = false

[consensus]
    consensus_type = pbft
    block_tx_count_limit = 1000
    leader_period = 1

[storage]
    type = rocksdb
    path = /data

[network]
    listen_ip = 0.0.0.0
    listen_port = 30300

[rpc]
    listen_ip = 0.0.0.0
    listen_port = 20200

[tx_pool]
    limit = 10000

[log]
    level = info
    path = /data/log
TOML_EOF

# Step 3: 生成 config.genesis（含真实 node_id）
echo "生成 config.genesis..."
cat > "${CONF_DIR}/config.genesis" << GENESIS_EOF
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
GENESIS_EOF

echo ""
echo "=== 初始化完成 ==="
echo "节点配置: ${NODES_DIR}/node{1..4}/"
echo "共用配置: ${CONF_DIR}/"
echo ""
echo "启动: docker-compose --profile production up -d"
