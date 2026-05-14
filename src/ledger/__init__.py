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

if IS_DEMO:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.info("联盟链: MockBCOS 进程内 (%d 节点模拟 PBFT)", CONSENSUS_NODE_COUNT)

elif IS_PRODUCTION_SIM:
    # 连接独立容器的 MockBCOS 节点
    _node_urls = os.environ.get("MOCK_NODE_URLS", "http://mock-node0:6000,http://mock-node1:6001,http://mock-node2:6002,http://mock-node3:6003")
    from src.debug.mock_bcos_client import MockBCOSClient
    # 返回工厂函数，因为每个 BCOSClient() 实例都共享同一个客户端
    _urls = [u.strip() for u in _node_urls.split(",")]
    BCOSClient = lambda: MockBCOSClient(node_urls=_urls)
    logger.info("联盟链: MockBCOS HTTP 远程 (%d 独立节点容器)", len(_urls))

elif IS_PRODUCTION:
    from src.ledger.bcos_client import BCOSClient
    logger.info("联盟链: FISCO BCOS SDK (生产模式)")

else:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.warning("未知模式，回退到 MockBCOS")
