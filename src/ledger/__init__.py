"""联盟链交互模块。

根据系统模式自动选择:
    debug            → MockBCOS (单进程模拟 PBFT 共识)
    production_sim   → 真实 BCOSClient (Docker 6 节点)
    production       → 真实 BCOSClient (服务器单节点)
"""

import logging

from src.config import IS_DEMO, IS_PRODUCTION_SIM, IS_PRODUCTION, CONSENSUS_NODE_COUNT

logger = logging.getLogger(__name__)

if IS_DEMO:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.info("联盟链模块: MockBCOS (demo 演示模式, %d 节点模拟 PBFT)", CONSENSUS_NODE_COUNT)
elif IS_PRODUCTION_SIM:
    from src.ledger.bcos_client import BCOSClient
    logger.info("联盟链模块: FISCO BCOS SDK (production_sim 模式, 连接 Docker 6 节点)")
elif IS_PRODUCTION:
    from src.ledger.bcos_client import BCOSClient
    logger.info("联盟链模块: FISCO BCOS SDK (production 模式, 服务器单节点)")
else:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
    logger.warning("未知模式，回退到 MockBCOS")
