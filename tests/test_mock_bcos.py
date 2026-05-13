"""MockBCOS自身功能测试。"""

import pytest

from src.debug.mock_bcos import MockBCOS, ChainIntegrityResult, ChainInfo, AuditRecord


class TestMockBCOSSpecial:
    def test_inject_record(self, mock_bcos):
        record = AuditRecord(
            batch_id="injected_001", merkle_root="a" * 64,
            prev_hash="0" * 64, record_hash="b" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="2026-05-08T14:25:00Z", log_count=10,
            tx_hash="mock_inject",
        )
        mock_bcos.inject_record(record)
        assert mock_bcos.query_by_batch_id("injected_001") is not None

    def test_tamper_record(self, mock_bcos):
        mock_bcos.record_audit(
            "batch_001", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
        )
        assert mock_bcos.tamper_record("batch_001", "merkle_root", "x" * 64) is True
        record = mock_bcos.query_by_batch_id("batch_001")
        assert record.merkle_root == "x" * 64

    def test_tamper_nonexistent(self, mock_bcos):
        assert mock_bcos.tamper_record("nonexistent", "merkle_root", "x") is False

    def test_delete_record(self, mock_bcos):
        mock_bcos.record_audit(
            "batch_001", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
        )
        assert mock_bcos.delete_record("batch_001") is True
        assert mock_bcos.query_by_batch_id("batch_001") is None

    def test_delete_nonexistent(self, mock_bcos):
        assert mock_bcos.delete_record("nonexistent") is False

    def test_dump_ledger(self, mock_bcos):
        mock_bcos.record_audit(
            "batch_001", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
        )
        data = mock_bcos.dump_ledger()
        assert data["latest_batch_id"] == "batch_001"
        assert len(data["records"]) == 1


class TestDataClasses:
    def test_chain_integrity_result(self):
        r = ChainIntegrityResult(is_valid=True, total_records=5, first_batch_id="b1", last_batch_id="b5")
        d = r.to_dict()
        assert d["is_valid"] is True
        assert d["total_records"] == 5

    def test_chain_info(self):
        info = ChainInfo(total_records=3, genesis_batch_id="b1", latest_batch_id="b3")
        d = info.to_dict()
        assert d["total_records"] == 3

    def test_audit_record_roundtrip(self):
        r = AuditRecord(
            batch_id="test", merkle_root="a" * 64,
            prev_hash="0" * 64, record_hash="b" * 64,
            signature="sig", signer_key_fp="fp",
            timestamp="t", log_count=42, tx_hash="tx",
        )
        d = r.to_dict()
        r2 = AuditRecord.from_dict(d)
        assert r2.batch_id == "test"
        assert r2.log_count == 42
