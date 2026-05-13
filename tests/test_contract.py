"""合约逻辑测试（使用MockBCOS）。"""

import hashlib
import pytest

from src.debug.mock_bcos import MockBCOS, GENESIS_PREV_HASH
from src.debug.data_generator import generate_batch
from src.merkle.tree import MerkleTree


class TestMockBCOS:
    def test_record_audit(self, mock_bcos):
        rh = mock_bcos.record_audit(
            batch_id="batch_001",
            merkle_root="a" * 64,
            signature="sig123",
            signer_key_fp="SHA256:fp123",
            timestamp="2026-05-08T14:25:00Z",
            log_count=100,
        )
        assert len(rh) == 64

    def test_prevent_duplicate_batch(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        with pytest.raises(ValueError, match="已存在"):
            mock_bcos.record_audit(
                batch_id="batch_001", merkle_root="b" * 64,
                signature="sig", signer_key_fp="fp",
                timestamp="2026-05-08T14:30:00Z", log_count=100,
            )

    def test_genesis_prev_hash(self, mock_bcos):
        rh = mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        record = mock_bcos.query_by_batch_id("batch_001")
        assert record.prev_hash == GENESIS_PREV_HASH

    def test_chain_structure(self, mock_bcos):
        rh1 = mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig1", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        rh2 = mock_bcos.record_audit(
            batch_id="batch_002", merkle_root="b" * 64,
            signature="sig2", signer_key_fp="fp",
            timestamp="2026-05-08T14:30:00Z", log_count=100,
        )
        r2 = mock_bcos.query_by_batch_id("batch_002")
        assert r2.prev_hash == rh1

    def test_verify_chain_valid(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig1", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        mock_bcos.record_audit(
            batch_id="batch_002", merkle_root="b" * 64,
            signature="sig2", signer_key_fp="fp",
            timestamp="2026-05-08T14:30:00Z", log_count=100,
        )
        result = mock_bcos.verify_chain_integrity()
        assert result.is_valid is True
        assert result.total_records == 2

    def test_verify_chain_tampered(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig1", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        mock_bcos.record_audit(
            batch_id="batch_002", merkle_root="b" * 64,
            signature="sig2", signer_key_fp="fp",
            timestamp="2026-05-08T14:30:00Z", log_count=100,
        )
        # 篡改
        mock_bcos.tamper_record("batch_002", "merkle_root", "x" * 64)
        result = mock_bcos.verify_chain_integrity()
        assert result.is_valid is False
        assert result.broken_position == 1

    def test_verify_chain_deleted_middle(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig1", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        mock_bcos.record_audit(
            batch_id="batch_002", merkle_root="b" * 64,
            signature="sig2", signer_key_fp="fp",
            timestamp="2026-05-08T14:30:00Z", log_count=100,
        )
        mock_bcos.record_audit(
            batch_id="batch_003", merkle_root="c" * 64,
            signature="sig3", signer_key_fp="fp",
            timestamp="2026-05-08T14:35:00Z", log_count=100,
        )
        # 删除中间批次 - 链断裂，因为batch_003的prev_hash指向batch_001的record_hash，
        # 但batch_001现在是第一条记录，其prev_hash应为全零
        mock_bcos.delete_record("batch_002")
        result = mock_bcos.verify_chain_integrity()
        # 删除后只剩batch_001和batch_003，batch_003的prev_hash不匹配
        assert result.is_valid is False

    def test_verify_record(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        assert mock_bcos.verify_record("batch_001", "a" * 64) is True
        assert mock_bcos.verify_record("batch_001", "b" * 64) is False
        assert mock_bcos.verify_record("nonexistent", "a" * 64) is False

    def test_get_chain_info(self, mock_bcos):
        info = mock_bcos.get_chain_info()
        assert info.total_records == 0

        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        info = mock_bcos.get_chain_info()
        assert info.total_records == 1
        assert info.genesis_batch_id == "batch_001"

    def test_time_range_query(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        mock_bcos.record_audit(
            batch_id="batch_002", merkle_root="b" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:30:00Z", log_count=100,
        )
        results = mock_bcos.query_by_time_range(
            "2026-05-08T14:25:00Z", "2026-05-08T14:25:59Z"
        )
        assert len(results) == 1
        assert results[0].batch_id == "batch_001"

    def test_reset_ledger(self, mock_bcos):
        mock_bcos.record_audit(
            batch_id="batch_001", merkle_root="a" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=100,
        )
        mock_bcos.reset_ledger()
        assert mock_bcos.get_chain_info().total_records == 0


class TestAuditLedgerContract:
    """测试真实的合约逻辑类（与MockBCOS逻辑一致）。"""

    @pytest.fixture
    def contract(self):
        from bcos.contract.audit_ledger import AuditLedger
        return AuditLedger()

    def test_full_flow(self, contract):
        rh1 = contract.record_audit(
            "batch_001", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
        )
        rh2 = contract.record_audit(
            "batch_002", "b" * 64, "sig", "fp",
            "2026-05-08T14:30:00Z", 200,
        )
        assert contract.total_records() == 2

        info = contract.get_chain_info()
        assert info["total_records"] == 2
        assert info["genesis_batch_id"] == "batch_001"

        result = contract.verify_chain_integrity()
        assert result["is_valid"] is True

        assert contract.verify_record("batch_001", "a" * 64) is True
        assert contract.verify_record("batch_001", "bad" * 21) is False

    def test_end_to_end_with_real_merkle(self, contract, sample_logs):
        """使用真实Merkle树构建的完整合约流程测试。"""
        tree = MerkleTree(sample_logs)
        merkle_root = tree.get_root()

        rh = contract.record_audit(
            "batch_e2e", merkle_root, "sig_real", "fp_real",
            "2026-05-08T14:25:00Z", len(sample_logs),
        )
        assert len(rh) == 64

        assert contract.verify_record("batch_e2e", merkle_root) is True


class TestAuditLedgerABI:
    """验证 Solidity 合约 ABI 定义的完整性和正确性。"""

    def test_abi_exported(self):
        from bcos.contract.audit_ledger import AuditLedgerABI
        assert AuditLedgerABI["contract_name"] == "AuditLedger"
        assert AuditLedgerABI["contract_version"] == "1.0.0"
        assert len(AuditLedgerABI["abi"]) > 0
        assert AuditLedgerABI["source_path"] == "bcos/contract/AuditLedger.sol"

    def test_abi_function_count(self):
        """ABI 中所有函数都存在。"""
        from bcos.contract.audit_ledger import AuditLedgerABI
        functions = [f for f in AuditLedgerABI["abi"] if f["type"] == "function"]
        names = {f["name"] for f in functions}
        expected = {
            "recordAudit", "totalRecords", "latestBatchId",
            "queryByBatchId", "verifyRecord", "verifyChainIntegrity",
            "getChainInfo", "queryByTimeRange",
        }
        assert names == expected, f"缺失函数: {expected - names}"

    def test_abi_event_count(self):
        from bcos.contract.audit_ledger import AuditLedgerABI
        events = [e for e in AuditLedgerABI["abi"] if e["type"] == "event"]
        names = {e["name"] for e in events}
        assert names == {"RecordAudited", "ChainVerified"}

    def test_abi_record_audit_signature(self):
        """recordAudit 函数的参数签名验证。"""
        from bcos.contract.audit_ledger import AuditLedgerABI
        func = next(f for f in AuditLedgerABI["abi"]
                    if f["type"] == "function" and f["name"] == "recordAudit")
        assert len(func["inputs"]) == 6
        input_names = [i["name"] for i in func["inputs"]]
        assert input_names == ["batchId", "merkleRoot", "signature",
                               "signerKeyFp", "timestamp", "logCount"]
        assert func["outputs"][0]["name"] == "recordHash"
        assert func["outputs"][0]["type"] == "string"

    def test_abi_verify_chain_integrity_outputs(self):
        """verifyChainIntegrity 的返回值验证。"""
        from bcos.contract.audit_ledger import AuditLedgerABI
        func = next(f for f in AuditLedgerABI["abi"]
                    if f["type"] == "function" and f["name"] == "verifyChainIntegrity")
        assert len(func["outputs"]) == 5
        output_names = [o["name"] for o in func["outputs"]]
        assert output_names == ["isValid", "totalRecords", "brokenPosition",
                                "genesisBatchId", "latestBatchId"]

    def test_solidity_source_exists(self):
        """合约源码文件存在。"""
        from bcos.contract.audit_ledger import AuditLedgerABI
        import os
        source_path = AuditLedgerABI["source_path"]
        assert os.path.exists(source_path), f"合约源码不存在: {source_path}"

    def test_solidity_source_contains_keywords(self):
        """合约源码包含核心关键字。"""
        source_path = "bcos/contract/AuditLedger.sol"
        with open(source_path, encoding="utf-8") as f:
            content = f.read()
        assert "contract AuditLedger" in content
        assert "sha256" in content
        assert "prevHash" in content
        assert "recordHash" in content
        assert "verifyChainIntegrity" in content
        assert "GENESIS_PREV_HASH" in content
        assert "mapping(bytes32 => bool)" in content
