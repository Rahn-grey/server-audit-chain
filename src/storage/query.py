"""链下查询与验证逻辑。

提供搜索操作日志、验证单条日志真伪的完整流程。
"""

import base64
import logging

from src.ledger.contract import AuditContract
from src.merkle.tree import MerkleTree, hash_leaf
from src.crypto.key_manager import load_public_key
from src.crypto.signer import verify
from src.storage import ESClient

logger = logging.getLogger(__name__)


class AuditQuery:
    """审计查询与验证。"""

    def __init__(self):
        self._es = ESClient()
        self._contract = AuditContract()

    def search_logs(self, operator: str | None = None,
                    start_time: str | None = None,
                    end_time: str | None = None,
                    keyword: str | None = None,
                    page: int = 1, size: int = 50) -> dict:
        """搜索操作日志。"""
        result = self._es.search_logs(
            operator=operator, start_time=start_time,
            end_time=end_time, keyword=keyword,
            page=page, size=size,
        )
        return result.to_dict()

    def verify_log(self, log_id: str, public_key_path: str | None = None) -> dict:
        """验证单条日志真伪。

        完整验证流程：
        1. 获取日志原文。
        2. 确定所属批次，取回批次内全部日志。
        3. 重建Merkle树，计算本地Merkle Root。
        4. 调用合约verify_record比对链上Merkle Root。
        5. 验签确认。
        6. 返回综合验证结果。

        Args:
            log_id: 日志ID。
            public_key_path: 验签公钥路径（可选）。

        Returns:
            验证结果字典，包含各步骤结果和最终判断。
        """
        logger.debug("验证日志 log_id=%s", log_id)

        # 1. 获取日志原文
        log_entry = self._es.get_log_by_id(log_id)
        if not log_entry:
            return {
                "log_id": log_id,
                "verified": False,
                "error": "log_not_found",
                "message": "日志未找到",
            }

        batch_id = log_entry.get("batch_id")
        if not batch_id:
            return {
                "log_id": log_id,
                "verified": False,
                "error": "batch_id_missing",
                "message": "日志缺少批次ID",
            }

        # 2. 取回批次内全部日志
        batch_logs = self._es.get_logs_by_batch(batch_id)
        logger.debug("批次 %s 共 %d 条日志", batch_id, len(batch_logs))

        # 3. 重建Merkle树，计算本地Merkle Root
        tree = MerkleTree(batch_logs)
        local_merkle_root = tree.get_root()
        logger.debug("本地Merkle Root: %s", local_merkle_root)

        # 4. 从链上查询该批次的存证记录
        chain_record = self._contract.query_by_batch_id(batch_id)
        if not chain_record:
            return {
                "log_id": log_id,
                "verified": False,
                "error": "batch_not_found",
                "message": f"批次 {batch_id} 在链上不存在",
            }

        chain_merkle_root = chain_record.get("merkle_root")
        logger.debug("链上Merkle Root: %s", chain_merkle_root)

        # 比对Merkle Root
        merkle_match = local_merkle_root == chain_merkle_root
        logger.debug("Merkle Root比对: %s", "一致" if merkle_match else "不一致")

        # 5. 验签（如果提供了公钥）
        signature_valid = None
        if public_key_path and chain_record.get("signature"):
            try:
                pub_key = load_public_key(public_key_path)
                data = (chain_record["prev_hash"] + chain_record["batch_id"] +
                        chain_record["merkle_root"] + chain_record["signature"] +
                        chain_record["timestamp"]).encode()
                sig_bytes = base64.b64decode(chain_record["signature"])
                signature_valid = verify(data, sig_bytes, pub_key)
                logger.debug("签名验证: %s", "通过" if signature_valid else "失败")
            except Exception as e:
                logger.warning("验签失败: %s", e)
                signature_valid = False

        # 6. 综合验证结果
        verified = merkle_match and (signature_valid is not False)

        result = {
            "log_id": log_id,
            "batch_id": batch_id,
            "verified": verified,
            "merkle_root_match": merkle_match,
            "signature_valid": signature_valid,
            "local_merkle_root": local_merkle_root,
            "chain_merkle_root": chain_merkle_root,
            "message": "验证通过" if verified else "验证失败",
        }

        if not merkle_match:
            result["error"] = "merkle_root_mismatch"
            result["message"] = "Merkle Root不一致，日志已被篡改"
        elif signature_valid is False:
            result["error"] = "signature_invalid"
            result["message"] = "签名无效"

        return result

    def verify_chain_integrity(self) -> dict:
        """验证整条审计链完整性。"""
        return self._contract.verify_chain()

    def get_chain_info(self) -> dict:
        """获取审计链摘要信息。"""
        return self._contract.get_chain_info()

    def get_record(self, batch_id: str) -> dict | None:
        """查询链上存证记录。"""
        return self._contract.query_by_batch_id(batch_id)
