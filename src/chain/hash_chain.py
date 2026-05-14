from __future__ import annotations
"""跨批次哈希链管理。

维护跨批次的哈希链，chain_hash = SHA256(prev_chain_hash + merkle_root)。
哈希链状态持久化至JSON文件。
"""

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64


class HashChain:
    """跨批次哈希链。"""

    def __init__(self, state_path: str | None = None):
        self.state_path = state_path
        self.chain = []
        self._latest_hash = None
        self._latest_batch_id = None
        if state_path and Path(state_path).exists():
            self._load()

    def _load(self):
        """从JSON文件加载哈希链状态。"""
        with open(self.state_path) as f:
            data = json.load(f)
        self.chain = data.get("chain", [])
        if self.chain:
            self._latest_hash = self.chain[-1]["chain_hash"]
            self._latest_batch_id = self.chain[-1]["batch_id"]
        logger.debug("从 %s 加载哈希链，共 %d 个批次", self.state_path, len(self.chain))

    def _save(self):
        """持久化哈希链状态至JSON文件。"""
        if not self.state_path:
            return
        Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w") as f:
            json.dump({"chain": self.chain}, f, indent=2, ensure_ascii=False)

    def add_batch(self, batch_id: str, merkle_root: str) -> str:
        """计算并添加新批次的链上哈希值。

        Args:
            batch_id: 批次唯一标识。
            merkle_root: 本批次Merkle Root。

        Returns:
            新批次的链哈希值。
        """
        prev_hash = self._latest_hash if self._latest_hash else GENESIS_PREV_HASH
        raw = (prev_hash + merkle_root).encode()
        chain_hash = hashlib.sha256(raw).hexdigest()

        entry = {
            "batch_id": batch_id,
            "prev_hash": prev_hash,
            "merkle_root": merkle_root,
            "chain_hash": chain_hash,
        }
        self.chain.append(entry)
        self._latest_hash = chain_hash
        self._latest_batch_id = batch_id
        self._save()

        logger.debug(
            "哈希链追加批次: batch_id=%s, chain_hash=%s", batch_id, chain_hash
        )
        return chain_hash

    def verify_chain(self) -> dict:
        """验证整条哈希链的连续性。

        Returns:
            {"is_valid": bool, "broken_position": int, "total": int}。
        """
        for i, entry in enumerate(self.chain):
            expected_prev = (
                GENESIS_PREV_HASH if i == 0 else self.chain[i - 1]["chain_hash"]
            )
            if entry["prev_hash"] != expected_prev:
                logger.warning("哈希链断裂于位置 %d", i)
                return {
                    "is_valid": False,
                    "broken_position": i,
                    "total": len(self.chain),
                }

            raw = (entry["prev_hash"] + entry["merkle_root"]).encode()
            expected_hash = hashlib.sha256(raw).hexdigest()
            if entry["chain_hash"] != expected_hash:
                logger.warning("哈希链数据篡改于位置 %d", i)
                return {
                    "is_valid": False,
                    "broken_position": i,
                    "total": len(self.chain),
                }

        logger.debug("哈希链完整性验证通过，共 %d 条记录", len(self.chain))
        return {"is_valid": True, "broken_position": -1, "total": len(self.chain)}

    def get_latest_hash(self) -> str:
        """返回最新批次的链哈希值。"""
        return self._latest_hash

    def get_chain_info(self) -> dict:
        """获取哈希链摘要信息。"""
        if not self.chain:
            return {
                "total_records": 0,
                "first_batch_id": None,
                "latest_batch_id": None,
                "latest_chain_hash": None,
            }
        return {
            "total_records": len(self.chain),
            "first_batch_id": self.chain[0]["batch_id"],
            "latest_batch_id": self.chain[-1]["batch_id"],
            "latest_chain_hash": self.chain[-1]["chain_hash"],
        }

    def reset(self):
        """重置哈希链（清空状态）。"""
        self.chain = []
        self._latest_hash = None
        self._latest_batch_id = None
        if self.state_path and Path(self.state_path).exists():
            Path(self.state_path).unlink(missing_ok=True)
        logger.debug("哈希链已重置")
