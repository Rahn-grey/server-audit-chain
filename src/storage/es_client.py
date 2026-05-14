from __future__ import annotations
"""Elasticsearch Python 客户端封装。

生产模式使用真实 ES。ES 不可用时优雅降级（日志警告 + 返回空结果），
系统核心链路（上链验证）不依赖 ES 可用性。
"""

import json
import logging
from datetime import datetime

from src.config import ES_HOST

logger = logging.getLogger(__name__)

# ES 是否可用（延迟探测）
_ES_AVAILABLE: bool | None = None  # None=未探测, True=可用, False=不可用


def _check_es_available() -> bool:
    """探测 ES 是否可用。只探测一次，结果缓存。"""
    global _ES_AVAILABLE
    if _ES_AVAILABLE is not None:
        return _ES_AVAILABLE
    try:
        from elasticsearch import Elasticsearch
        client = Elasticsearch([ES_HOST])
        _ES_AVAILABLE = client.ping()
    except Exception:
        _ES_AVAILABLE = False
    if not _ES_AVAILABLE:
        logger.warning("ES 不可用 (%s)，日志存储降级: 仅上链存证，不存储原文",
                      ES_HOST)
    else:
        logger.info("ES 已连接: %s", ES_HOST)
    return _ES_AVAILABLE


class SearchResult:
    """搜索结果（与 MockES.SearchResult 接口一致）。"""
    def __init__(self, results: list, total: int, page: int, size: int):
        self.results = results
        self.total = total
        self.page = page
        self.size = size

    def to_dict(self) -> dict:
        return {
            "results": self.results,
            "total": self.total,
            "page": self.page,
            "size": self.size,
        }


class ESClient:
    """Elasticsearch 客户端封装。

    ES 可用时: 全功能存储和搜索
    ES 不可用时: 优雅降级，日志原文仅上链存证（不存储原文），
               搜索返回空结果，不影响核心审计链路。
    """

    def __init__(self, host: str | None = None):
        self.host = host or ES_HOST
        self._client = None
        self._available = False
        self.connect()

    def connect(self):
        """建立 ES 连接。ES 不可用时静默降级。"""
        self._available = _check_es_available()
        if self._available:
            try:
                from elasticsearch import Elasticsearch
                self._client = Elasticsearch([self.host])
                logger.info("ES 已连接: %s", self.host)
            except Exception as e:
                logger.warning("ES 连接失败: %s，使用降级模式", e)
                self._available = False

    def disconnect(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def bulk_index(self, logs: list[dict], index_prefix: str = "server-audit"):
        """批量写入日志到 ES。

        ES 不可用时静默跳过（日志原文仅上链存证，不影响审计完整性）。
        """
        if not logs:
            return
        if not self._available:
            logger.debug("ES 不可用，跳过日志原文存储 (%d 条)", len(logs))
            return

        today = datetime.now().strftime("%Y-%m-%d")
        index_name = f"{index_prefix}-{today}"

        try:
            body_lines = []
            for log in logs:
                log_id = log.get("log_id", "")
                body_lines.append(json.dumps({
                    "index": {"_index": index_name, "_id": log_id}
                }))
                body_lines.append(json.dumps(log, ensure_ascii=False))
            body = "\n".join(body_lines) + "\n"
            self._client.bulk(body=body)
            logger.info("批量写入 %d 条日志到 ES 索引 %s", len(logs), index_name)
        except Exception as e:
            logger.error("ES 批量写入失败: %s (%d 条日志未存储)", e, len(logs))

    def inject_logs(self, logs: list[dict]):
        """兼容 MockES 接口名。"""
        self.bulk_index(logs)

    # ------------------------------------------------------------------
    # 搜索
    # ------------------------------------------------------------------

    def search_logs(self, operator: str | None = None,
                    start_time: str | None = None,
                    end_time: str | None = None,
                    keyword: str | None = None,
                    page: int = 1, size: int = 50) -> SearchResult:
        """搜索日志（与 MockES 接口一致）。

        ES 不可用时返回空结果。
        """
        if not self._available:
            return SearchResult(results=[], total=0, page=page, size=size)

        today = datetime.now().strftime("%Y-%m-%d")
        index_pattern = "server-audit-*"

        try:
            must = []
            if operator:
                must.append({"match": {"operator": operator}})
            if keyword:
                must.append({"match": {"command": keyword}})
            if start_time or end_time:
                range_q = {"timestamp": {}}
                if start_time:
                    range_q["timestamp"]["gte"] = start_time
                if end_time:
                    range_q["timestamp"]["lte"] = end_time
                must.append({"range": range_q})

            query = {"query": {"bool": {"must": must}}} if must else {"query": {"match_all": {}}}

            result = self._client.search(
                index=index_pattern,
                body=query,
                size=size,
                from_=(page - 1) * size,
                sort=[{"timestamp": "desc"}],
            )

            hits = result["hits"]["hits"]
            total = result["hits"]["total"]
            if isinstance(total, dict):
                total = total["value"]

            results = [h["_source"] for h in hits]
            logger.debug("ES 搜索: operator=%s keyword=%s → %d 条",
                        operator, keyword, total)
            return SearchResult(results=results, total=total, page=page, size=size)

        except Exception as e:
            logger.error("ES 搜索失败: %s", e)
            return SearchResult(results=[], total=0, page=page, size=size)

    def get_log_by_id(self, log_id: str,
                      index_prefix: str = "server-audit") -> dict | None:
        """按 ID 获取单条日志。"""
        if not self._available:
            return None
        try:
            result = self._client.get(
                index=f"{index_prefix}-*", id=log_id, ignore=[404])
            if result.get("found"):
                return result["_source"]
            return None
        except Exception as e:
            logger.error("ES get_log_by_id 失败: %s", e)
            return None

    def get_logs_by_batch(self, batch_id: str,
                          index_prefix: str = "server-audit") -> list[dict]:
        """获取指定批次的所有日志。"""
        if not self._available:
            return []
        try:
            query = {"query": {"match": {"batch_id": batch_id}}, "size": 10000}
            result = self._client.search(index=f"{index_prefix}-*", body=query)
            return [h["_source"] for h in result["hits"]["hits"]]
        except Exception as e:
            logger.error("ES get_logs_by_batch 失败: %s", e)
            return []

    def get_all_logs(self) -> list[dict]:
        """获取所有日志。"""
        if not self._available:
            return []
        try:
            query = {"query": {"match_all": {}}, "size": 10000,
                    "sort": [{"timestamp": "desc"}]}
            result = self._client.search(index="server-audit-*", body=query)
            return [h["_source"] for h in result["hits"]["hits"]]
        except Exception as e:
            logger.error("ES get_all_logs 失败: %s", e)
            return []

    # ------------------------------------------------------------------
    # Debug 兼容
    # ------------------------------------------------------------------

    def reset_logs(self):
        """清空日志（兼容 MockES 接口，生产模式不建议调用）。"""
        if not self._available:
            return
        logger.warning("ES reset_logs: 生产模式不建议清空索引")

    def tamper_log(self, log_id: str, field: str, new_value: str) -> bool:
        """篡改日志（兼容 MockES 接口，仅测试用）。"""
        if not self._available:
            return False
        log = self.get_log_by_id(log_id)
        if not log:
            return False
        log[field] = new_value
        try:
            idx = f"server-audit-{datetime.now().strftime('%Y-%m-%d')}"
            self._client.index(index=idx, id=log_id, body=log)
            logger.warning("ES tamper_log: log_id=%s field=%s", log_id, field)
            return True
        except Exception as e:
            logger.error("ES tamper_log 失败: %s", e)
            return False
