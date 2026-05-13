"""Merkle树单元测试。"""

import hashlib
import pytest

from src.merkle.tree import MerkleTree, hash_leaf, hash_pair
from src.merkle.proof import generate_proof, verify_proof


class TestMerkleTree:
    def test_empty_tree(self):
        tree = MerkleTree([])
        root = tree.get_root()
        assert len(root) == 64
        assert root == hashlib.sha256(b"").hexdigest()

    def test_single_leaf(self):
        logs = [{"log_id": "1", "command": "ls"}]
        tree = MerkleTree(logs)
        root = tree.get_root()
        assert len(root) == 64
        assert tree.leaf_count == 1

    def test_two_leaves(self):
        logs = [
            {"log_id": "1", "command": "ls"},
            {"log_id": "2", "command": "cat"},
        ]
        tree = MerkleTree(logs)
        root = tree.get_root()
        assert tree.leaf_count == 2

    def test_odd_leaves(self):
        logs = [
            {"log_id": "1", "command": "ls"},
            {"log_id": "2", "command": "cat"},
            {"log_id": "3", "command": "grep"},
        ]
        tree = MerkleTree(logs)
        root = tree.get_root()
        assert tree.leaf_count == 3
        assert tree.get_level_count() >= 2

    def test_deterministic_root(self):
        logs = [
            {"log_id": "1", "command": "ls"},
            {"log_id": "2", "command": "cat"},
        ]
        tree1 = MerkleTree(logs)
        tree2 = MerkleTree(logs)
        assert tree1.get_root() == tree2.get_root()

    def test_different_logs_different_root(self):
        logs_a = [{"log_id": "1", "command": "ls"}]
        logs_b = [{"log_id": "1", "command": "rm"}]
        root_a = MerkleTree(logs_a).get_root()
        root_b = MerkleTree(logs_b).get_root()
        assert root_a != root_b


class TestMerkleProof:
    def test_proof_verify(self):
        logs = [
            {"log_id": f"{i}", "command": f"cmd_{i}"}
            for i in range(10)
        ]
        tree = MerkleTree(logs)
        root = tree.get_root()

        for i in range(10):
            leaf_hash = tree.get_leaf_hash(i)
            proof = generate_proof(tree, i)
            assert verify_proof(leaf_hash, proof, root)

    def test_proof_reject_wrong_leaf(self):
        logs = [
            {"log_id": "1", "command": "ls"},
            {"log_id": "2", "command": "cat"},
        ]
        tree = MerkleTree(logs)
        root = tree.get_root()

        # 用错误的叶子哈希验证
        wrong_hash = hashlib.sha256(b"fake").hexdigest()
        proof = generate_proof(tree, 0)
        assert not verify_proof(wrong_hash, proof, root)

    def test_proof_out_of_range(self):
        tree = MerkleTree([{"log_id": "1"}])
        with pytest.raises(IndexError):
            generate_proof(tree, 5)

    def test_proof_single_leaf(self):
        logs = [{"log_id": "1", "command": "ls"}]
        tree = MerkleTree(logs)
        proof = generate_proof(tree, 0)
        assert len(proof) == 0  # 只有根节点，没有额外证明路径
        assert verify_proof(tree.get_leaf_hash(0), proof, tree.get_root())
