"""联盟链交互模块。

根据系统模式自动选择:
    demo              → MockBCOS (进程内共享单例)
    production_sim    → MockBCOS HTTP 远程客户端 (Docker 4 独立节点)
    production        → 真实 FISCO BCOS 客户端 (服务器节点)
"""

import logging
import os

from src.config import IS_DEMO, IS_PRODUCTION_SIM, IS_PRODUCTION, CONSENSUS_NODE_COUNT

logger = logging.getLogger(__name__)

# 如果设置了 MOCK_NODE_URLS，强制使用 HTTP 远程客户端
_mock_urls = os.environ.get("MOCK_NODE_URLS")
if _mock_urls:
    from src.debug.mock_bcos_client import MockBCOSClient
    _urls = [u.strip() for u in _mock_urls.split(",")]
    BCOSClient = lambda: MockBCOSClient(node_urls=_urls)
    logger.info("联盟链: MockBCOS HTTP 远程 (%d 独立节点容器)", len(_urls))

elif IS_DEMO:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.info("联盟链: MockBCOS 进程内 (%d 节点模拟 PBFT)", CONSENSUS_NODE_COUNT)

elif IS_PRODUCTION_SIM:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.info("联盟链: MockBCOS 进程内 (生产模拟, 未配置远程节点)")

elif IS_PRODUCTION:
    from src.ledger.bcos_client import BCOSClient
    logger.info("联盟链: FISCO BCOS SDK (生产模式)")

else:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.warning("未知模式，回退到 MockBCOS")
