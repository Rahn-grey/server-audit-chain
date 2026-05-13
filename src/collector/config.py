"""采集层配置。

环境变量:
    COLLECTOR_MODE:       direct | bastion | both
    COLLECTOR_LOG_FILE:   监听日志文件路径（direct模式）
    COLLECTOR_BATCH_SECS: 批次时间窗口秒数（硬上限）
    COLLECTOR_API_URL:    审计API地址
    COLLECTOR_LISTEN_PORT: 堡垒机接收端口（bastion模式）
"""

import os

# ---- 采集模式 ----
COLLECTOR_MODE = os.environ.get("COLLECTOR_MODE", "direct")
# direct    — 监听本地日志文件
# bastion   — 接收堡垒机上传统接口
# both      — 同时运行两种模式

# ---- 直接采集配置 ----
COLLECTOR_LOG_FILE = os.environ.get(
    "COLLECTOR_LOG_FILE", "/var/log/audit/commands.log"
)

# ---- 批次配置 ----
COLLECTOR_BATCH_SECS = int(os.environ.get("COLLECTOR_BATCH_SECS", "300"))

# ---- API 地址 ----
COLLECTOR_API_URL = os.environ.get(
    "COLLECTOR_API_URL", "http://127.0.0.1:5000/api/v1/audit/batch"
)

# ---- 堡垒机接收配置 ----
COLLECTOR_LISTEN_HOST = os.environ.get("COLLECTOR_LISTEN_HOST", "0.0.0.0")
COLLECTOR_LISTEN_PORT = int(os.environ.get("COLLECTOR_LISTEN_PORT", "5001"))
