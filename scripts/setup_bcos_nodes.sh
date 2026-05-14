#!/bin/bash
# ================================================================
# FISCO BCOS 3.0.0 节点初始化
# 生成节点密钥 + 创世配置
# 用法: bash scripts/setup_bcos_nodes.sh
# ================================================================

set -e
BCOS_IMAGE="fiscoorg/fiscobcos:v3.0.0"
NODES_DIR="bcos/nodes"
CONF_DIR="bcos/conf"
NODE_COUNT=6

mkdir -p "${NODES_DIR}" "${CONF_DIR}"

echo "=== FISCO BCOS 3.0.0 节点初始化 ==="

# Step 1: 生成每个节点的密钥
NODE_IDS=()
for i in $(seq 1 $NODE_COUNT); do
    NODE_DIR="${NODES_DIR}/node${i}"
    mkdir -p "${NODE_DIR}"

    if [ ! -f "${NODE_DIR}/node.pem" ]; then
        echo "[${i}/${NODE_COUNT}] 生成 node${i} 密钥..."
        openssl genpkey -algorithm Ed25519 -out "${NODE_DIR}/node.pem" 2>/dev/null
    fi

    # node_id = sha256(公钥) = 64字符hex
    NODE_ID=$(openssl pkey -in "${NODE_DIR}/node.pem" -pubout 2>/dev/null | \
        sha256sum | cut -d' ' -f1)
    NODE_IDS+=("${NODE_ID}")
    echo "  node${i}: ${NODE_ID}"
done

echo ""

# Step 2: 生成 config.toml
echo "生成 config.toml..."
cat > "${CONF_DIR}/config.toml" << 'TOML_EOF'
[chain]
id=1
sm_crypto=false

[consensus]
consensus_type=pbft
block_tx_count_limit=1000
leader_period=1

[security]
private_key_path=/data/node.pem

[storage]
type=rocksdb
path=/data

[network]
listen_ip=0.0.0.0
listen_port=30300

[rpc]
listen_ip=0.0.0.0
listen_port=20200

[tx_pool]
limit=10000

[log]
level=info
path=/data/log
TOML_EOF

# Step 3: 生成 config.genesis（INI格式，无缩进）
echo "生成 config.genesis..."
cat > "${CONF_DIR}/config.genesis" << GENESIS_EOF
[consensus]
consensus_type=pbft
block_tx_count_limit=1000
leader_period=1
node.0=${NODE_IDS[0]}
node.1=${NODE_IDS[1]}
node.2=${NODE_IDS[2]}
node.3=${NODE_IDS[3]}
node.4=${NODE_IDS[4]}
node.5=${NODE_IDS[5]}

[tx]
gas_limit=3000000000

[executor]
is_wasm=false
is_auth_check=false
GENESIS_EOF

echo ""
echo "=== 初始化完成 ==="
echo "节点配置: ${NODES_DIR}/node{1..${NODE_COUNT}}/"
echo "共用配置: ${CONF_DIR}/ (config.toml + config.genesis)"
echo ""
echo "启动: docker-compose --profile production_sim up -d"
