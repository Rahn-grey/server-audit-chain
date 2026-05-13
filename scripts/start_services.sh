#!/bin/bash
# 启动所有服务（BCOS网络 + Elasticsearch + 应用API）
# Debug模式下，仅启动Flask API并启用MockBCOS和MockES

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# 获取模式
MODE="${AUDIT_SYSTEM_MODE:-debug}"

echo "=== 启动服务器操作审计系统 ==="
echo "系统模式: $MODE"
echo ""

if [ "$MODE" = "production" ]; then
    echo "1. 启动FISCO BCOS网络..."
    bash "$SCRIPT_DIR/start_bcos.sh"

    echo ""
    echo "2. 启动Elasticsearch..."
    cd "$PROJECT_DIR"
    docker-compose up -d elasticsearch kibana

    echo ""
    echo "3. 等待ES就绪..."
    sleep 10
else
    echo "Debug模式: 跳过外部依赖启动"
    echo "使用MockBCOS和MockES替代FISCO BCOS和Elasticsearch"
fi

echo ""
echo "4. 启动Flask API服务..."
cd "$PROJECT_DIR"

export AUDIT_SYSTEM_MODE="$MODE"
export FLASK_APP=src.api.routes
export FLASK_ENV=development

# 生成密钥对（如果不存在）
KEYS_DIR="$PROJECT_DIR/keys"
if [ ! -f "$KEYS_DIR/audit_private.pem" ]; then
    echo "生成Ed25519签名密钥对..."
    python "$SCRIPT_DIR/generate_keys.py" --output-dir "$KEYS_DIR"
fi

# 启动Flask
echo "Flask API启动于 http://127.0.0.1:5000"
python -m flask run --host 0.0.0.0 --port 5000
