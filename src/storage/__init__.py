"""链下存储模块。

根据系统模式自动选择:
    debug            → MockES (SQLite 模拟)
    production_sim   → ESClient (Docker ES)
    production       → ESClient (服务器 ES)
"""

import logging

from src.config import IS_DEMO, IS_PRODUCTION_SIM, IS_PRODUCTION

logger = logging.getLogger(__name__)

if IS_DEMO:
    from src.debug.mock_es import MockES as ESClient
    logger.info("存储模块: MockES (SQLite)")
elif IS_PRODUCTION_SIM:
    from src.storage.es_client import ESClient
    logger.info("存储模块: Elasticsearch (production_sim 模式)")
elif IS_PRODUCTION:
    from src.storage.es_client import ESClient
    logger.info("存储模块: Elasticsearch (production 模式)")
else:
    from src.debug.mock_es import MockES as ESClient
    logger.warning("未知模式，回退到 MockES")
