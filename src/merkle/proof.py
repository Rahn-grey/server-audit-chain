"""Merkle证明生成与验证。"""

import hashlib
import logging

from src.merkle.tree import hash_pair

logger = logging.getLogger(__name__)


def generate_proof(tree, leaf_index: int) -> list:
    """生成指定叶子的Merkle证明路径。

    Args:
        tree: MerkleTree对象。
        leaf_index: 叶子节点的索引（0-based）。

    Returns:
        证明路径列表，每个元素为 (sibling_hash, is_left)，
        is_left为True表示兄弟节点在左侧。
    """
    if leaf_index < 0 or leaf_index >= tree.leaf_count:
        raise IndexError(
            f"leaf_index {leaf_index} 超出范围 [0, {tree.leaf_count})"
        )

    proof = []
    idx = leaf_index

    # 从叶子层开始，每一层收集兄弟节点
    for level_idx in range(len(tree.levels) - 1):
        level = tree.levels[level_idx]
        # 处理奇数补齐的情况
        if len(level) % 2 == 1:
            level = level + [level[-1]]

        sibling_idx = idx ^ 1  # 奇偶互换得到兄弟索引
        if sibling_idx < len(level):
            is_left = sibling_idx < idx
            proof.append((level[sibling_idx], is_left))
        idx //= 2

    logger.debug("Merkle证明路径长度: %d", len(proof))
    return proof


def verify_proof(leaf_hash: str, proof_path: list, root: str) -> bool:
    """验证Merkle证明。

    Args:
        leaf_hash: 叶子节点的哈希值。
        proof_path: generate_proof()返回的证明路径。
        root: Merkle Root哈希值。

    Returns:
        True表示验证通过。
    """
    current = leaf_hash

    for sibling_hash, is_left in proof_path:
        if is_left:
            current = hash_pair(sibling_hash, current)
        else:
            current = hash_pair(current, sibling_hash)

    result = current == root
    logger.debug("Merkle证明验证: %s", "通过" if result else "失败")
    return result
