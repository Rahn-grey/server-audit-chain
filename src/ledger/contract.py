from __future__ import annotations
"""合约调用封装。

提供对审计合约各函数的便捷调用接口。
根据系统模式自动使用MockBCOS或真实BCOS客户端。
"""

import logging

from src.ledger import BCOSClient

logger = logging.getLogger(__name__)


class AuditContract:
    """审计合约调用封装。"""

    def __init__(self):
        self._client = BCOSClient()

    def submit_audit_record(self, batch_id: str, merkle_root: str,
                            signature: str, signer_key_fp: str,
                            timestamp: str, log_count: int) -> str:
        """调用合约record_audit函数上链存证。

        Returns:
            record_hash字符串。
        """
        logger.info("提交审计记录: batch_id=%s", batch_id)
        record_hash = self._client.record_audit(
            batch_id, merkle_root, signature,
            signer_key_fp, timestamp, log_count,
        )
        logger.info("上链成功: record_hash=%s", record_hash)
        return record_hash

    def verify_chain(self) -> dict:
        """调用合约verify_chain_integrity函数验证整链完整性。"""
        logger.info("验证整链完整性")
        result = self._client.verify_chain_integrity()
        return result.to_dict()

    def query_by_batch_id(self, batch_id: str) -> dict | None:
        """查询链上存证记录。"""
        record = self._client.query_by_batch_id(batch_id)
        return record.to_dict() if record else None

    def verify_record(self, batch_id: str, merkle_root: str) -> bool:
        """验证指定批次记录。"""
        return self._client.verify_record(batch_id, merkle_root)

    def get_chain_info(self) -> dict:
        """获取链摘要信息。"""
        info = self._client.get_chain_info()
        return info.to_dict()

    def query_by_time_range(self, start_time: str, end_time: str) -> list:
        """按时间范围查询。"""
        records = self._client.query_by_time_range(start_time, end_time)
        return [r.to_dict() for r in records]

    # ------------------------------------------------------------------
    # 联盟链共识接口 (MockBCOS PBFT)
    # ------------------------------------------------------------------

    def get_consensus_status(self) -> dict:
        """获取联盟链共识网络状态。"""
        if hasattr(self._client, "get_consensus_status"):
            return self._client.get_consensus_status()
        return {"message": "共识状态仅 debug 模式可用"}

    def get_cross_verify(self) -> dict:
        """跨节点账本一致性验证。"""
        if hasattr(self._client, "cross_verify"):
            return self._client.cross_verify()
        return {"message": "跨节点验证仅 debug 模式可用"}

    def simulate_attack(self) -> dict:
        """模拟拜占庭攻击（仅debug模式）。"""
        if hasattr(self._client, "simulate_byzantine_attack"):
            return self._client.simulate_byzantine_attack()
        return {"message": "攻击模拟仅 debug 模式可用"}
