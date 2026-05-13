"""Merkle树构建与Merkle Root计算。"""

import hashlib
import json
import logging

logger = logging.getLogger(__name__)


def hash_leaf(data: dict) -> str:
    """计算日志条目的SHA-256叶子哈希。

    将字典按key排序后序列化为JSON再哈希，确保可复现性。
    """
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """拼接两个子节点的哈希并计算父节点哈希。"""
    combined = left + right
    return hashlib.sha256(combined.encode()).hexdigest()


class MerkleTree:
    """Merkle树。"""

    def __init__(self, leaves: list):
        """从日志条目列表构建Merkle树。"""
        self.leaves = [hash_leaf(entry) for entry in leaves]
        self.leaf_count = len(self.leaves)
        self.levels = self._build(self.leaves)
        logger.debug(
            "构建Merkle树，叶子节点数: %d, 树深度: %d",
            self.leaf_count,
            len(self.levels),
        )

    def _build(self, leaf_hashes: list) -> list:
        """自底向上构建Merkle树的所有层次。

        Args:
            leaf_hashes: 叶子哈希列表。

        Returns:
            各层节点哈希列表的列表，levels[0]为叶子层，levels[-1][0]为根。
        """
        if not leaf_hashes:
            empty = hashlib.sha256(b"").hexdigest()
            return [[empty]]

        levels = [leaf_hashes[:]]
        current = leaf_hashes[:]

        while len(current) > 1:
            # 奇数个节点时复制最后一个补齐
            if len(current) % 2 == 1:
                current.append(current[-1])

            next_level = []
            for i in range(0, len(current), 2):
                parent = hash_pair(current[i], current[i + 1])
                next_level.append(parent)
            levels.append(next_level)
            current = next_level

        logger.debug("Merkle Root: %s", current[0])
        return levels

    def get_root(self) -> str:
        """返回Merkle Root（64字符十六进制）。"""
        if not self.levels:
            return hashlib.sha256(b"").hexdigest()
        return self.levels[-1][0]

    def get_level_count(self) -> int:
        """返回树的总层数。"""
        return len(self.levels)

    def get_leaf_hash(self, index: int) -> str:
        """返回指定索引的叶子哈希。"""
        return self.leaves[index]
