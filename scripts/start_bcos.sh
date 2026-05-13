#!/bin/bash
# 启动FISCO BCOS 4节点联盟网络（Docker Compose方式）
# 注意：需安装docker和docker-compose

set -e

NETWORK_NAME="bcos_network"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== 启动FISCO BCOS 4节点联盟网络 ==="

# 检查docker
if ! command -v docker &> /dev/null; then
    echo "错误: 未安装Docker，请先安装Docker"
    exit 1
fi

# 检查docker-compose
if ! command -v docker-compose &> /dev/null; then
    echo "错误: 未安装docker-compose"
    exit 1
fi

# 检查节点配置文件
CONFIG_DIR="$PROJECT_DIR/bcos/conf"
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    echo "错误: 未找到节点配置文件 $CONFIG_DIR/config.toml"
    exit 1
fi

# 创建docker网络
docker network ls | grep -q "$NETWORK_NAME" || docker network create "$NETWORK_NAME"

# 启动节点
echo "启动BCOS节点..."
cd "$PROJECT_DIR"
docker-compose -f docker-compose.yml up -d bcos-node1 bcos-node2 bcos-node3 bcos-node4

echo "等待节点启动..."
sleep 5

echo ""
echo "=== FISCO BCOS网络已启动 ==="
echo "节点: node1 node2 node3 node4"
echo "查看日志: docker-compose logs -f bcos-node1"
echo "停止网络: docker-compose down"
