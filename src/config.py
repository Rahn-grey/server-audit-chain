import os

# ====================================================================
# 系统运行模式（3 种）
# ====================================================================
#   demo              — MockBCOS 单进程模拟 + SQLite，零依赖一键演示
#   production_sim    — Docker 4节点 FISCO BCOS + ES，本地联盟链测试 (6容器)
#   production        — 服务器 FISCO BCOS 单节点 + ES，真实部署
#                       (生产模式默认输出详细步骤日志)
# ====================================================================
SYSTEM_MODE = os.environ.get("AUDIT_SYSTEM_MODE", "demo")

# 模式判断
IS_DEMO = SYSTEM_MODE == "demo"
IS_PRODUCTION_SIM = SYSTEM_MODE == "production_sim"
IS_PRODUCTION = SYSTEM_MODE == "production"
IS_REAL_BCOS = IS_PRODUCTION_SIM or IS_PRODUCTION  # 需要真实 FISCO BCOS

# ---- 生产模式详细日志 ----
# 生产模式默认输出每一步操作的详细日志（与演示模式同级别）
VERBOSE_LOG = os.environ.get("AUDIT_VERBOSE_LOG",
                             "true" if IS_PRODUCTION else "true").lower() == "true"

# ---- 演示模式数据路径 ----
DEMO_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "debug_data")
DEMO_LEDGER_FILE = os.path.join(DEMO_DATA_DIR, "debug_ledger.json")
DEMO_LOGS_FILE = os.path.join(DEMO_DATA_DIR, "audit_logs.db")

# 兼容旧变量名
DEBUG_DATA_DIR = DEMO_DATA_DIR
DEBUG_LEDGER_FILE = DEMO_LEDGER_FILE
DEBUG_LOGS_FILE = DEMO_LOGS_FILE

# ---- 生产模拟模式配置 ----
# Docker 本地 6 节点联盟链
BCOS_SIM_CONFIG = {
    "nodes": [
        "127.0.0.1:20200",   # node1
        "127.0.0.1:20201",   # node2
        "127.0.0.1:20202",   # node3
        "127.0.0.1:20203",   # node4
    ],
    "endpoint": os.environ.get("BCOS_ENDPOINT", "127.0.0.1:20200"),
    "contract_address": os.environ.get("BCOS_CONTRACT_ADDR", ""),
}

# ---- 生产模式配置 ----
# 连接服务器上的单个 BCOS 节点
BCOS_CONFIG = {
    "endpoint": os.environ.get("BCOS_ENDPOINT", "127.0.0.1:20200"),
    "contract_address": os.environ.get("BCOS_CONTRACT_ADDR", ""),
}

# ES 配置（生产模拟 和 生产 共用）
ES_HOST = os.environ.get("ES_HOST", "localhost:9200")

# 批次配置
BATCH_WINDOW_MINUTES = int(os.environ.get("BATCH_WINDOW_MINUTES", "5"))
BATCH_MAX_LOG_COUNT = int(os.environ.get("BATCH_MAX_LOG_COUNT", "10000"))

# 日志配置
LOG_LEVEL = os.environ.get("AUDIT_LOG_LEVEL", "DEBUG" if IS_DEMO or VERBOSE_LOG else "INFO")

# 共识节点数（demo模式MockBCOS / production_sim Docker一致）
CONSENSUS_NODE_COUNT = int(os.environ.get("CONSENSUS_NODE_COUNT", "4"))
