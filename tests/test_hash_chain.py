"""哈希链单元测试。"""

import hashlib
import pytest

from src.chain.hash_chain import HashChain, GENESIS_PREV_HASH


class TestHashChain:
    def test_empty_chain(self):
        chain = HashChain()
        info = chain.get_chain_info()
        assert info["total_records"] == 0
        assert info["first_batch_id"] is None

    def test_add_one_batch(self):
        chain = HashChain()
        h = chain.add_batch("batch_001", "abc" * 21)  # 63 chars -> need 64
        assert len(h) == 64
        assert chain.get_latest_hash() == h

    def test_chain_continuity(self):
        chain = HashChain()
        h1 = chain.add_batch("batch_001", "a" * 64)
        h2 = chain.add_batch("batch_002", "b" * 64)

        assert chain.chain[1]["prev_hash"] == h1
        assert chain.chain[1]["chain_hash"] == h2

    def test_genesis_prev_hash(self):
        chain = HashChain()
        chain.add_batch("batch_001", "a" * 64)
        assert chain.chain[0]["prev_hash"] == GENESIS_PREV_HASH

    def test_verify_valid_chain(self):
        chain = HashChain()
        chain.add_batch("batch_001", "a" * 64)
        chain.add_batch("batch_002", "b" * 64)
        chain.add_batch("batch_003", "c" * 64)

        result = chain.verify_chain()
        assert result["is_valid"] is True
        assert result["broken_position"] == -1

    def test_verify_invalid_chain_tampered(self):
        chain = HashChain()
        chain.add_batch("batch_001", "a" * 64)
        chain.add_batch("batch_002", "b" * 64)

        # 篡改chain_hash
        chain.chain[1]["chain_hash"] = "f" * 64
        result = chain.verify_chain()
        assert result["is_valid"] is False

    def test_verify_broken_prev_hash(self):
        chain = HashChain()
        chain.add_batch("batch_001", "a" * 64)
        chain.add_batch("batch_002", "b" * 64)

        # 篡改prev_hash
        chain.chain[1]["prev_hash"] = "e" * 64
        result = chain.verify_chain()
        assert result["is_valid"] is False
        assert result["broken_position"] == 1

    def test_reset(self):
        chain = HashChain()
        chain.add_batch("batch_001", "a" * 64)
        chain.reset()
        assert len(chain.chain) == 0
        assert chain.get_latest_hash() is None

    def test_chain_hash_same_input(self):
        chain1 = HashChain()
        chain2 = HashChain()
        h1 = chain1.add_batch("same_batch", "a" * 64)
        h2 = chain2.add_batch("same_batch", "a" * 64)
        # 都是创世的第一条，结果应相同
        assert h1 == h2

    def test_chain_hash_different_order(self):
        chain = HashChain()
        h1 = chain.add_batch("batch_001", "a" * 64)
        h2 = chain.add_batch("batch_002", "b" * 64)
        # 验证h2 != SHA256(genesis + b*64)
        raw = (GENESIS_PREV_HASH + "b" * 64).encode()
        expected_if_first = hashlib.sha256(raw).hexdigest()
        assert h2 != expected_if_first  # 因为h2的prev_hash是h1而不是genesis
