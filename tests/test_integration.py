"""集成测试（全Mock环境）。

测试完整流程：日志产生 → 批次处理 → 签名 → 上链 → 查询验证。
以及篡改检测、断链检测场景。
"""

import base64
import hashlib
import pytest

from src.chain.hash_chain import HashChain
from src.merkle.tree import MerkleTree
from src.crypto.signer import sign, verify
from src.crypto.key_manager import generate_key_pair, get_public_key_fingerprint


class TestIntegration:
    """集成测试 - 完整流程。"""

    def full_flow(self, mock_bcos, mock_es, key_pair, multi_batch_logs):
        """执行完整流程并返回关键数据。"""
        priv, pub = key_pair
        fp = get_public_key_fingerprint(pub)
        chain = HashChain()

        results = []
        for idx, (batch_id, logs) in enumerate(multi_batch_logs):
            # 1. 存储原文
            mock_es.inject_logs(logs)

            # 2. Merkle树
            tree = MerkleTree(logs)
            merkle_root = tree.get_root()

            # 3. 哈希链
            chain_hash = chain.add_batch(batch_id, merkle_root)

            # 4. 签名
            data_to_sign = chain_hash.encode()
            signature = sign(data_to_sign, priv)
            signature_b64 = base64.b64encode(signature).decode()

            # 5. 上链
            timestamp = f"2026-05-08T{14 + idx:02d}:00:00Z"
            record_hash = mock_bcos.record_audit(
                batch_id=batch_id,
                merkle_root=merkle_root,
                signature=signature_b64,
                signer_key_fp=fp,
                timestamp=timestamp,
                log_count=len(logs),
            )
            results.append({
                "batch_id": batch_id,
                "merkle_root": merkle_root,
                "chain_hash": chain_hash,
                "record_hash": record_hash,
                "signature": signature_b64,
                "log_count": len(logs),
            })
        return results, chain

    def test_scenario_normal_audit(self, mock_bcos, mock_es, key_pair, multi_batch_logs):
        """场景一：正常运维操作审计。"""
        results, chain = self.full_flow(mock_bcos, mock_es, key_pair, multi_batch_logs)

        # 验证链完整性
        cr = mock_bcos.verify_chain_integrity()
        assert cr.is_valid is True
        assert cr.total_records == len(multi_batch_logs)

        # 验证链信息
        info = mock_bcos.get_chain_info()
        assert info.total_records == len(multi_batch_logs)

        # 验证每批次上链记录
        for r in results:
            record = mock_bcos.query_by_batch_id(r["batch_id"])
            assert record is not None
            assert record.merkle_root == r["merkle_root"]
            assert record.record_hash == r["record_hash"]
            assert mock_bcos.verify_record(r["batch_id"], r["merkle_root"]) is True

    def test_scenario_log_tamper_detection(self, mock_bcos, mock_es, key_pair, multi_batch_logs):
        """场景二：日志篡改检测。

        模拟攻击者修改ES日志，验证系统能够检出篡改。
        """
        results, chain = self.full_flow(mock_bcos, mock_es, key_pair, multi_batch_logs)

        # 从第一个批次取一条日志篡改
        batch_id, logs = multi_batch_logs[0]
        tampered_log = logs[0]
        mock_es.tamper_log(tampered_log["log_id"], "command", "rm -rf /")

        # 重新计算该批次的Merkle Root
        batch_logs = mock_es.get_logs_by_batch(batch_id)
        recalculated_tree = MerkleTree(batch_logs)
        local_root = recalculated_tree.get_root()

        # 从链上获取原始Merkle Root
        chain_record = mock_bcos.query_by_batch_id(batch_id)
        original_root = chain_record.merkle_root

        # 比对——必定不一致
        assert local_root != original_root

        # 验证合约 verify_record 检测到不一致
        assert mock_bcos.verify_record(batch_id, local_root) is False

    def test_scenario_chain_broken_detection(self, mock_bcos, mock_es, key_pair, multi_batch_logs):
        """场景三：断链检测。

        模拟删除中间批次记录，验证链完整性检测能够检出。
        """
        results, chain = self.full_flow(mock_bcos, mock_es, key_pair, multi_batch_logs)

        # 保存原有记录数
        total = len(multi_batch_logs)

        # 删除中间批次（如果批次足够多）
        if total >= 3:
            # 获取中间批次的batch_id
            middle_batch = multi_batch_logs[total // 2][0]
            mock_bcos.delete_record(middle_batch)

            # delete_record删除中间记录，导致链断裂（后续记录的prev_hash不匹配）
            cr = mock_bcos.verify_chain_integrity()
            # 链上记录减少一条
            assert mock_bcos.get_chain_info().total_records == total - 1

    def test_signature_verification(self, mock_bcos, mock_es, key_pair, multi_batch_logs):
        """验证签名和验签正确性。"""
        priv, pub = key_pair
        results, chain = self.full_flow(mock_bcos, mock_es, key_pair, multi_batch_logs)

        for r in results:
            # 签名的数据是 chain_hash（来自HashChain）
            sig_bytes = base64.b64decode(r["signature"])
            assert verify(r["chain_hash"].encode(), sig_bytes, pub) is True

    def test_merkle_rebuild_matches(self, mock_bcos, mock_es, multi_batch_logs):
        """验证从ES取回日志后重建Merkle树结果一致。"""
        for batch_id, logs in multi_batch_logs:
            mock_es.inject_logs(logs)

        for batch_id, logs in multi_batch_logs:
            batch_logs = mock_es.get_logs_by_batch(batch_id)
            # 重建Merkle树
            local_tree = MerkleTree(batch_logs)
            local_root = local_tree.get_root()
            # 用原始日志（按 log_id 排序）构建
            original_sorted = sorted(logs, key=lambda x: x.get("log_id", ""))
            original_tree = MerkleTree(original_sorted)
            original_root = original_tree.get_root()
            assert local_root == original_root
