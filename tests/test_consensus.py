"""联盟链 PBFT 共识 + 拜占庭节点防御测试。

测试场景:
    场景A: 4节点0拜占庭 → PBFT正常共识
    场景B: 4节点1拜占庭 → 共识别达成 (3个诚实节点 ≥2f+1)
    场景C: 拜占庭节点篡改本地数据 → 跨节点验证检出
    场景D: PBFT共识过程投票日志验证
    场景E: 全网拜占庭节点数超限 → 初始化拒绝
    场景F: 与单节点 MockBCOS 的兼容性
"""

import pytest

from src.debug.mock_bcos import (
    MockBCOS,
    MockNode,
    MockConsensusNetwork,
    NodeVote,
    ChainIntegrityResult,
    ChainInfo,
    AuditRecord,
)


# ======================================================================
# Fixtures
# ======================================================================

def _make_record_args(batch_id="batch_001", merkle_root=None):
    """构造 record_audit 参数。"""
    if merkle_root is None:
        merkle_root = "abcd" * 16  # 64-char hex
    return dict(
        batch_id=batch_id,
        merkle_root=merkle_root,
        signature="base64sig",
        signer_key_fp="SHA256:abcdef",
        timestamp="2026-05-13T14:30:00Z",
        log_count=100,
    )


# ======================================================================
# 场景A: 4节点0拜占庭 → PBFT正常共识
# ======================================================================

class TestNormalConsensus:
    """正常 PBFT 共识（无拜占庭节点）。"""

    def test_create_network(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=0)
        assert net.num_nodes == 4
        assert len(net.nodes) == 4
        assert all(n.is_honest for n in net.nodes)
        assert net._quorum == 1  # 2*0+1 = 1

    def test_single_record_consensus(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=0)
        args = _make_record_args("batch_001")
        rh = net.record_audit(**args)
        assert len(rh) == 64  # SHA256 hex

        # 所有4个节点都应有该记录
        for node in net.nodes:
            assert node.record_count == 1

    def test_multi_record_consensus(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=0)
        for i in range(5):
            args = _make_record_args(f"batch_{i:03d}")
            rh = net.record_audit(**args)
            assert len(rh) == 64

        # 所有节点都应该有5条记录
        for node in net.nodes:
            assert node.record_count == 5

    def test_chain_integrity_after_consensus(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=0)
        for i in range(3):
            args = _make_record_args(f"batch_{i:03d}")
            net.record_audit(**args)

        result = net.verify_chain_integrity()
        assert result.is_valid is True
        assert result.total_records == 3

    def test_cross_verify_all_honest(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=0)
        for i in range(3):
            args = _make_record_args(f"batch_{i:03d}")
            net.record_audit(**args)

        report = net.cross_verify()
        assert report["consensus_ok"] is True
        assert report["honest_nodes_match"] is True
        assert report["byzantine_detected"] is False

    def test_duplicate_batch_id_rejected(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=0)
        args = _make_record_args("batch_dup")
        net.record_audit(**args)

        with pytest.raises(ValueError, match="已存在"):
            net.record_audit(**args)


# ======================================================================
# 场景B: 4节点1拜占庭 → PBFT共识达成 (3诚实 ≥ 2f+1=3)
# ======================================================================

class TestByzantineTolerance:
    """PBFT 容忍拜占庭节点。"""

    def test_consensus_with_one_byzantine(self):
        """1个拜占庭节点不应阻止共识，因为3个诚实节点 ≥ 3票(quorum)。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        assert len(net.nodes) == 4
        assert sum(1 for n in net.nodes if n.is_honest) == 3
        assert sum(1 for n in net.nodes if not n.is_honest) == 1
        assert net._quorum == 3  # 2*1+1 = 3

    def test_record_with_byzantine_present(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        args = _make_record_args("batch_001")

        # 共识应成功（3个诚实节点 ≥ 3票）
        rh = net.record_audit(**args)
        assert len(rh) == 64

        # 3个诚实节点应有记录
        honest_count = sum(1 for n in net.nodes if n.is_honest and n.record_count == 1)
        assert honest_count == 3, f"期望3个诚实节点有记录, 实际{honest_count}"

    def test_multi_round_with_byzantine(self):
        """多轮共识，每轮都有拜占庭干扰但共识达成。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        for i in range(10):
            args = _make_record_args(f"batch_{i:03d}")
            # 不应抛异常（共识每次都应达标）
            rh = net.record_audit(**args)
            assert len(rh) == 64

        # 最终验证
        result = net.verify_chain_integrity()
        assert result.is_valid is True
        assert result.total_records == 10

    def test_byzantine_node_may_have_fewer_records(self):
        """拜占庭节点可能拒绝投票，所以账本可能不完整。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        for i in range(20):
            args = _make_record_args(f"batch_{i:03d}")
            net.record_audit(**args)

        # 诚实节点应有全部20条
        for node in net.nodes:
            if node.is_honest:
                assert node.record_count == 20


# ======================================================================
# 场景C: 拜占庭攻击 → 跨节点验证检出
# ======================================================================

class TestByzantineDetection:
    """拜占庭篡改检测。"""

    def test_byzantine_attack_detected_by_cross_verify(self):
        """拜占庭节点篡改本地账本后，跨节点验证可检出。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)

        # 正常共识 3 轮
        for i in range(3):
            args = _make_record_args(f"batch_{i:03d}")
            net.record_audit(**args)

        # 攻击前验证 —— 应该正常
        before = net.cross_verify()
        # 拜占庭节点可能在查询时返回不一致数据，也可能正常
        # 关键测试在攻击后

        # 模拟拜占庭攻击
        attack = net.simulate_byzantine_attack()
        assert attack["success"] is True

        # 攻击后跨节点验证
        after = net.cross_verify()
        assert after["byzantine_detected"] is True, \
            f"拜占庭攻击应被检出! detail={after['details']}"
        assert after["consensus_ok"] is False

    def test_honest_nodes_remain_consistent_after_attack(self):
        """拜占庭攻击只影响攻击节点，诚实节点间仍一致。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        for i in range(3):
            args = _make_record_args(f"batch_{i:03d}")
            net.record_audit(**args)

        net.simulate_byzantine_attack()

        report = net.cross_verify()
        assert report["byzantine_detected"] is True
        # 诚实节点之间应该一致
        assert report["honest_nodes_match"] is True, \
            f"诚实节点间不应有分歧! detail={report['details']}"

    def test_network_status_report(self):
        """网络状态报告包含所有节点的诊断信息。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        for i in range(2):
            args = _make_record_args(f"batch_{i:03d}")
            net.record_audit(**args)

        status = net.get_network_status()
        assert "config" in status
        assert "PBFT" in status["config"]["consensus_algorithm"]
        assert len(status["nodes"]) == 4
        assert status["nodes"][0]["type"] == "honest"
        assert status["nodes"][3]["type"] == "byzantine"


# ======================================================================
# 场景D: PBFT 投票日志详细验证
# ======================================================================

class TestPBFTVotingLog:
    """PBFT 投票过程可审计。"""

    def test_consensus_log_contains_votes(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        net.record_audit(**_make_record_args("batch_001"))

        assert len(net._consensus_log) == 1
        round_info = net._consensus_log[0]

        # Phase 1: 广播
        assert "broadcast_from" in round_info["phase1"]

        # Phase 2: 投票详情
        p2 = round_info["phase2"]
        assert p2["total_votes"] == 4
        assert "votes" in p2
        assert len(p2["votes"]) == 4

    def test_pbft_phases_in_order(self):
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        net.record_audit(**_make_record_args("test_phases"))

        log = net._consensus_log[0]
        assert "broadcast_from" in log["phase1"]
        assert isinstance(log["phase2"], dict)
        assert isinstance(log["phase3"], dict)
        assert log["phase3"]["status"] == "committed"


# ======================================================================
# 场景E: 拜占庭节点数超限
# ======================================================================

class TestFaultThreshold:
    """PBFT 容错边界。"""

    def test_two_fault_in_four_nodes_rejected(self):
        """N=4时最大容错 f=1, f=2应被拒绝。"""
        with pytest.raises(ValueError, match="PBFT"):
            MockConsensusNetwork(num_nodes=4, fault_nodes=2)

    def test_one_fault_in_four_nodes_accepted(self):
        """N=4时 f=1 在 PBFT 容错范围内。"""
        net = MockConsensusNetwork(num_nodes=4, fault_nodes=1)
        assert net._f == 1

    def test_seven_nodes_two_faults_ok(self):
        """N=7时 f≤2 在容错范围内。"""
        net = MockConsensusNetwork(num_nodes=7, fault_nodes=2)
        assert net._f == 2
        assert net._quorum == 5  # 2*2+1=5


# ======================================================================
# 场景F: MockBCOS 向后兼容性
# ======================================================================

class TestBackwardCompatibility:
    """MockBCOS 单节点接口不变。"""

    def test_mock_bcos_records(self, mock_bcos):
        mock_bcos.record_audit(
            "batch_001", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
        )
        assert mock_bcos.query_by_batch_id("batch_001") is not None
        assert mock_bcos.get_chain_info().total_records == 1

    def test_mock_bcos_integrity(self, mock_bcos):
        for i in range(3):
            mock_bcos.record_audit(
                f"batch_{i:03d}", chr(ord('a') + i) * 64,
                "sig", "fp", f"2026-05-08T14:{i:02d}:00Z", 100,
            )
        result = mock_bcos.verify_chain_integrity()
        assert result.is_valid is True
        assert result.total_records == 3

    def test_mock_node_honest(self):
        node = MockNode("leader", is_honest=True)
        node.commit_record(
            "batch_001", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
            record_hash="b" * 64, prev_hash="0" * 64,
            tx_hash="tx_001",
        )
        assert node.record_count == 1
        assert node.node_status == "honest"

    def test_mock_node_byzantine(self):
        node = MockNode("evil_node", is_honest=False)
        node.commit_record(
            "batch_evil", "a" * 64, "sig", "fp",
            "2026-05-08T14:25:00Z", 100,
            record_hash="b" * 64, prev_hash="0" * 64,
            tx_hash="tx_evil",
        )
        # 拜占庭节点查询时可能返回篡改数据
        record = node.query_by_batch_id("batch_evil")
        assert record is not None

    def test_node_vote(self):
        vote = NodeVote("node_0", "agree", "a" * 64, "0" * 64)
        assert vote.vote == "agree"
        d = vote.to_dict()
        assert d["node_id"] == "node_0"
        assert d["vote"] == "agree"
