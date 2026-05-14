"""MockBCOS - 模拟 FISCO BCOS 联盟链 + PBFT 共识。

架构:
    MockBCOS (外部接口，共享单例)
       └── MockConsensusNetwork (PBFT 共识网络, 6节点)
              └── MockNode × 6 (每节点独立账本, 诚实/拜占庭)

演示模式零依赖（demo mode）:
    - 链式存证: record_hash = SHA256(prev_hash + batch_id + merkle_root + sig + time)
    - PBFT 共识: Pre-Prepare → Prepare(投票) → Commit(≥2f+1 诚实票)
    - 拜占庭容错: 6 节点可容忍 1 个作恶节点 (f=1)
    - 跨节点验证: 比对全部账本，检出不一致节点
"""

import hashlib
import json
import logging
import random
from pathlib import Path

from src.config import DEBUG_LEDGER_FILE

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64


# ======================================================================
# 数据类
# ======================================================================

class ChainIntegrityResult:
    def __init__(self, is_valid: bool, total_records: int,
                 broken_position: int = -1,
                 first_batch_id: str | None = None,
                 last_batch_id: str | None = None):
        self.is_valid = is_valid
        self.total_records = total_records
        self.broken_position = broken_position
        self.first_batch_id = first_batch_id
        self.last_batch_id = last_batch_id

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "total_records": self.total_records,
            "broken_position": self.broken_position,
            "first_batch_id": self.first_batch_id,
            "last_batch_id": self.last_batch_id,
        }


class ChainInfo:
    def __init__(self, total_records=0, genesis_batch_id=None,
                 genesis_time=None, latest_batch_id=None,
                 latest_time=None, latest_record_hash=None):
        self.total_records = total_records
        self.genesis_batch_id = genesis_batch_id
        self.genesis_time = genesis_time
        self.latest_batch_id = latest_batch_id
        self.latest_time = latest_time
        self.latest_record_hash = latest_record_hash

    def to_dict(self) -> dict:
        return {
            "total_records": self.total_records,
            "genesis_batch_id": self.genesis_batch_id,
            "genesis_time": self.genesis_time,
            "latest_batch_id": self.latest_batch_id,
            "latest_time": self.latest_time,
            "latest_record_hash": self.latest_record_hash,
        }


class AuditRecord:
    def __init__(self, batch_id, merkle_root, prev_hash, record_hash,
                 signature, signer_key_fp, timestamp, log_count, tx_hash):
        self.batch_id = batch_id
        self.merkle_root = merkle_root
        self.prev_hash = prev_hash
        self.record_hash = record_hash
        self.signature = signature
        self.signer_key_fp = signer_key_fp
        self.timestamp = timestamp
        self.log_count = log_count
        self.tx_hash = tx_hash

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "merkle_root": self.merkle_root,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
            "signature": self.signature,
            "signer_key_fp": self.signer_key_fp,
            "timestamp": self.timestamp,
            "log_count": self.log_count,
            "tx_hash": self.tx_hash,
        }

    @staticmethod
    def from_dict(d: dict):
        return AuditRecord(
            batch_id=d["batch_id"],
            merkle_root=d["merkle_root"],
            prev_hash=d["prev_hash"],
            record_hash=d["record_hash"],
            signature=d["signature"],
            signer_key_fp=d["signer_key_fp"],
            timestamp=d["timestamp"],
            log_count=d["log_count"],
            tx_hash=d["tx_hash"],
        )


# ======================================================================
# MockNode — 联盟链节点
# ======================================================================

class MockNode:
    """联盟链共识节点，维护独立账本副本。

    honest:    诚实节点，正确计算 record_hash，正确返回数据
    byzantine: 拜占庭节点，投票时返回错误 hash，查询时可能返回篡改数据
    """

    def __init__(self, node_id: str, is_honest: bool = True):
        self.node_id = node_id
        self.is_honest = is_honest
        self._records: list[AuditRecord] = []

    @staticmethod
    def _compute_record_hash(prev_hash: str, batch_id: str,
                             merkle_root: str, signature: str,
                             timestamp: str) -> str:
        raw = (prev_hash + batch_id + merkle_root + signature + timestamp).encode()
        return hashlib.sha256(raw).hexdigest()

    def commit_record(self, batch_id: str, merkle_root: str,
                      signature: str, signer_key_fp: str,
                      timestamp: str, log_count: int,
                      record_hash: str, prev_hash: str, tx_hash: str):
        record = AuditRecord(
            batch_id=batch_id, merkle_root=merkle_root,
            prev_hash=prev_hash, record_hash=record_hash,
            signature=signature, signer_key_fp=signer_key_fp,
            timestamp=timestamp, log_count=log_count, tx_hash=tx_hash,
        )
        self._records.append(record)

    def propose(self, batch_id: str, merkle_root: str,
                signature: str, signer_key_fp: str,
                timestamp: str, log_count: int) -> "NodeVote":
        """PBFT Prepare 阶段投票。

        诚实节点: 正确计算 record_hash → agree
        拜占庭: 随机返回错误 hash 或拒绝
        """
        for r in self._records:
            if r.batch_id == batch_id:
                return NodeVote(node_id=self.node_id, vote="reject",
                                record_hash="", reason="batch_id_duplicate")

        prev_hash = (self._records[-1].record_hash
                     if self._records else GENESIS_PREV_HASH)

        if self.is_honest:
            rh = self._compute_record_hash(
                prev_hash, batch_id, merkle_root, signature, timestamp)
            return NodeVote(node_id=self.node_id, vote="agree",
                           record_hash=rh, prev_hash=prev_hash)
        else:
            if random.random() < 0.5:
                logger.warning("[BYZANTINE] 节点 %s 返回篡改 hash", self.node_id)
                return NodeVote(node_id=self.node_id, vote="agree",
                               record_hash=hashlib.sha256(b"EVIL").hexdigest(),
                               prev_hash=prev_hash)
            else:
                logger.warning("[BYZANTINE] 节点 %s 拒绝投票", self.node_id)
                return NodeVote(node_id=self.node_id, vote="reject",
                                record_hash="", reason="byzantine_refuse")

    def query_by_batch_id(self, batch_id: str) -> AuditRecord | None:
        for r in self._records:
            if r.batch_id == batch_id:
                if self.is_honest:
                    return r
                if random.random() < 0.6:
                    tampered = AuditRecord(
                        batch_id=r.batch_id,
                        merkle_root=hashlib.sha256(b"TAMPER").hexdigest(),
                        prev_hash=r.prev_hash, record_hash=r.record_hash,
                        signature=r.signature, signer_key_fp=r.signer_key_fp,
                        timestamp=r.timestamp, log_count=r.log_count,
                        tx_hash=r.tx_hash,
                    )
                    logger.warning("[BYZANTINE] 节点 %s 查询返回篡改数据: %s",
                                 self.node_id, batch_id)
                    return tampered
                return r
        return None

    def verify_chain_integrity(self) -> ChainIntegrityResult:
        total = len(self._records)
        if total == 0:
            return ChainIntegrityResult(is_valid=True, total_records=0)
        first, last = self._records[0], self._records[-1]
        for i, r in enumerate(self._records):
            expected_prev = (GENESIS_PREV_HASH if i == 0
                           else self._records[i - 1].record_hash)
            if r.prev_hash != expected_prev:
                return ChainIntegrityResult(
                    is_valid=False, total_records=total, broken_position=i,
                    first_batch_id=first.batch_id, last_batch_id=last.batch_id)
            expected = self._compute_record_hash(
                r.prev_hash, r.batch_id, r.merkle_root, r.signature, r.timestamp)
            if r.record_hash != expected:
                return ChainIntegrityResult(
                    is_valid=False, total_records=total, broken_position=i,
                    first_batch_id=first.batch_id, last_batch_id=last.batch_id)
        return ChainIntegrityResult(
            is_valid=True, total_records=total,
            first_batch_id=first.batch_id, last_batch_id=last.batch_id)

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def node_status(self) -> str:
        return "honest" if self.is_honest else "byzantine"


class NodeVote:
    def __init__(self, node_id: str, vote: str, record_hash: str,
                 prev_hash: str = "", reason: str = ""):
        self.node_id = node_id
        self.vote = vote
        self.record_hash = record_hash
        self.prev_hash = prev_hash
        self.reason = reason

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "vote": self.vote,
            "record_hash": (self.record_hash[:16] + "..."
                           if self.record_hash else ""),
            "reason": self.reason,
        }


# ======================================================================
# MockConsensusNetwork — PBFT 联盟链共识网络
# ======================================================================

class MockConsensusNetwork:
    """PBFT 共识网络 — debug 模式下的完整区块链实现。

    4 节点, 1 拜占庭, PBFT 三阶段投票, 跨节点验证。
    node_0 为创世节点（Leader），负责 Pre-Prepare 提议。
    """

    def __init__(self, num_nodes: int = 4, fault_nodes: int = 1):
        if fault_nodes > (num_nodes - 1) // 3:
            raise ValueError(
                f"PBFT 要求 f ≤ (N-1)/3 = {(num_nodes - 1) // 3}，"
                f"当前 fault_nodes={fault_nodes}")
        self.num_nodes = num_nodes
        self.fault_nodes = fault_nodes
        self._f = fault_nodes
        self._quorum = 2 * self._f + 1

        self.nodes: list[MockNode] = []
        for i in range(num_nodes):
            is_honest = i < (num_nodes - fault_nodes)
            self.nodes.append(MockNode(f"node_{i}", is_honest=is_honest))

        # 创世节点 = 第一个诚实节点，负责 Pre-Prepare 提议
        self.genesis_node_id = "node_0"

        self._consensus_log: list[dict] = []
        self._tx_counter = 0

        honest_count = sum(1 for n in self.nodes if n.is_honest)
        logger.info("联盟链共识网络启动: %d 节点 (%d 诚实/%d 拜占庭) | "
                    "创世节点=%s | PBFT quorum=%d | "
                    "共识: Pre-Prepare(L)→Prepare→Commit",
                    num_nodes, honest_count, self.genesis_node_id, self._quorum)

    # ==================================================================
    # PBFT 共识 — 核心上链入口
    # ==================================================================

    def record_audit(self, batch_id: str, merkle_root: str,
                     signature: str, signer_key_fp: str,
                     timestamp: str, log_count: int) -> str:
        """PBFT 三阶段共识上链。

        Phase 1 Pre-Prepare: 广播提议
        Phase 2 Prepare:     各节点独立投票 (agree/reject)
        Phase 3 Commit:      诚实票 ≥ 2f+1 → 写入所有节点
        """
        # 预检查: batch_id 是否已存在
        leader = self._leader()
        for r in leader._records:
            if r.batch_id == batch_id:
                raise ValueError(f"batch_id '{batch_id}' 已存在")

        self._tx_counter += 1
        rnd = {"round": self._tx_counter, "batch_id": batch_id}

        # Phase 1: Pre-Prepare
        logger.info("[PBFT-%d] Pre-Prepare(L=%s) → 广播 batch_id=%s",
                   self._tx_counter, self.genesis_node_id, batch_id)
        rnd["phase1"] = f"broadcast_from_{self.genesis_node_id}"

        # Phase 2: Prepare — 各节点投票
        logger.info("[PBFT-%d] Prepare → 节点投票", self._tx_counter)
        votes = [n.propose(batch_id, merkle_root, signature,
                          signer_key_fp, timestamp, log_count)
                for n in self.nodes]
        agrees = [v for v in votes if v.vote == "agree"]
        rejects = [v for v in votes if v.vote == "reject"]
        honest_agrees = [v for v in agrees
                        if self.nodes[int(v.node_id.split("_")[1])].is_honest]

        rnd["phase2"] = {
            "total_votes": len(votes),
            "agree": len(agrees), "reject": len(rejects),
            "honest_agree": len(honest_agrees),
            "quorum_needed": self._quorum,
            "votes": [v.to_dict() for v in votes],
        }
        logger.info("[PBFT-%d] 投票: agree=%d reject=%d honest=%d quorum=%d",
                   self._tx_counter, len(agrees), len(rejects),
                   len(honest_agrees), self._quorum)

        # Phase 3: Commit
        if len(honest_agrees) < self._quorum:
            logger.error("[PBFT-%d] ❌ 共识失败: 诚实票 %d < quorum %d",
                        self._tx_counter, len(honest_agrees), self._quorum)
            rnd["phase3"] = "consensus_failed"
            self._consensus_log.append(rnd)
            raise ValueError(
                f"PBFT 共识失败: 需 ≥{self._quorum} 诚实票, "
                f"实际 {len(honest_agrees)}")

        final_rh = honest_agrees[0].record_hash
        final_ph = honest_agrees[0].prev_hash
        tx_hash = f"pbft_tx_{self._tx_counter:04d}"

        for n in self.nodes:
            n.commit_record(batch_id, merkle_root, signature,
                           signer_key_fp, timestamp, log_count,
                           final_rh, final_ph, tx_hash)

        logger.info("[PBFT-%d] ✅ 共识达成: record_hash=%s",
                   self._tx_counter, final_rh[:16])
        rnd["phase3"] = {"status": "committed", "record_hash": final_rh,
                         "tx_hash": tx_hash}
        self._consensus_log.append(rnd)
        return final_rh

    # ==================================================================
    # 查询
    # ==================================================================

    def _leader(self) -> MockNode:
        """获取创世节点（node_0），负责 Pre-Prepare 提议。"""
        return self.nodes[0]

    def query_by_batch_id(self, batch_id: str) -> AuditRecord | None:
        return self._leader().query_by_batch_id(batch_id)

    def query_by_time_range(self, start_time: str,
                            end_time: str) -> list[AuditRecord]:
        leader = self._leader()
        return [r for r in leader._records
                if start_time <= r.timestamp <= end_time]

    def verify_chain_integrity(self) -> ChainIntegrityResult:
        return self._leader().verify_chain_integrity()

    def get_chain_info(self) -> ChainInfo:
        recs = self._leader()._records
        if not recs:
            return ChainInfo()
        return ChainInfo(
            total_records=len(recs),
            genesis_batch_id=recs[0].batch_id,
            genesis_time=recs[0].timestamp,
            latest_batch_id=recs[-1].batch_id,
            latest_time=recs[-1].timestamp,
            latest_record_hash=recs[-1].record_hash,
        )

    def verify_record(self, batch_id: str, merkle_root: str) -> bool:
        for n in self.nodes:
            if n.is_honest:
                for r in n._records:
                    if r.batch_id == batch_id:
                        return r.merkle_root == merkle_root
        return False

    # ==================================================================
    # 拜占庭攻击模拟
    # ==================================================================

    def simulate_byzantine_attack(self, node_index: int = -1) -> dict:
        if node_index < 0:
            for i, n in enumerate(self.nodes):
                if not n.is_honest:
                    node_index = i
                    break
            if node_index < 0:
                return {"success": False,
                       "message": "没有拜占庭节点 (fault_nodes=0)"}
        node = self.nodes[node_index]
        if node.is_honest or node.record_count == 0:
            return {"success": False,
                   "message": "目标节点不是拜占庭或账本为空"}
        target = node._records[-1]
        old_merkle = target.merkle_root
        target.merkle_root = hashlib.sha256(b"BYZANTINE_ATTACK").hexdigest()
        logger.warning("[ATTACK] 拜占庭节点 %s 篡改 batch_id=%s",
                      node.node_id, target.batch_id)
        return {"success": True, "node_id": node.node_id,
                "batch_id": target.batch_id,
                "old_merkle_root": old_merkle,
                "new_merkle_root": target.merkle_root}

    def cross_verify(self) -> dict:
        honest = [n for n in self.nodes if n.is_honest]
        byz = [n for n in self.nodes if not n.is_honest]
        result = {
            "consensus_ok": True,
            "honest_nodes_match": True,
            "byzantine_detected": False,
            "total_nodes": len(self.nodes),
            "honest_nodes": len(honest),
            "byzantine_nodes": len(byz),
            "details": {},
        }
        # 诚实节点间比对
        if len(honest) >= 2:
            ref = honest[0]
            for i, n in enumerate(honest[1:], 1):
                if n.record_count != ref.record_count:
                    result["honest_nodes_match"] = False
                    result["consensus_ok"] = False
                else:
                    for j in range(n.record_count):
                        if n._records[j].record_hash != ref._records[j].record_hash:
                            result["honest_nodes_match"] = False
                            result["consensus_ok"] = False
                            break
        # 拜占庭节点比对
        if honest and byz:
            ref = honest[0]
            for n in byz:
                detected = False
                if n.record_count != ref.record_count:
                    detected = True
                else:
                    for j in range(min(n.record_count, ref.record_count)):
                        if (n._records[j].record_hash != ref._records[j].record_hash or
                            n._records[j].merkle_root != ref._records[j].merkle_root):
                            detected = True
                            break
                if detected:
                    result["byzantine_detected"] = True
                    result["consensus_ok"] = False
                    result["details"][n.node_id] = (
                        f"拜占庭节点 {n.node_id} 与诚实节点账本不一致")
                    logger.warning("[SECURITY] 拜占庭节点 %s 被跨节点验证检出!",
                                 n.node_id)
        if result["consensus_ok"]:
            result["summary"] = "[OK] 联盟链健康: 所有诚实节点账本一致"
        else:
            result["summary"] = "[WARN] 联盟链异常: 存在不一致节点"
        return result

    def get_network_status(self) -> dict:
        nodes_status = []
        for n in self.nodes:
            ci = n.verify_chain_integrity()
            nodes_status.append({
                "node_id": n.node_id,
                "type": n.node_status,
                "record_count": n.record_count,
                "chain_valid": ci.is_valid,
                "latest_hash": (n._records[-1].record_hash[:16]
                               if n._records else "N/A"),
            })
        return {
            "config": {
                "total_nodes": self.num_nodes,
                "genesis_node": self.genesis_node_id,
                "consensus_algorithm": "PBFT (Practical Byzantine Fault Tolerance)",
                "fault_tolerance": f"f={self._f}, 可容忍 {self._f} 拜占庭节点",
                "quorum": f"2f+1={self._quorum}",
                "flow": f"Pre-Prepare({self.genesis_node_id}) → Prepare(投票) → Commit",
            },
            "nodes": nodes_status,
            "latest_consensus": (self._consensus_log[-1]
                                if self._consensus_log else None),
            "cross_verify": self.cross_verify()["summary"],
        }

    # ==================================================================
    # Debug 工具
    # ==================================================================

    def reset_ledger(self):
        for n in self.nodes:
            n._records = []
        self._consensus_log = []
        self._tx_counter = 0
        logger.info("联盟链网络已重置")

    def tamper_record(self, batch_id: str, field: str,
                      new_value: str) -> bool:
        for n in self.nodes:
            if n.is_honest:
                for r in n._records:
                    if r.batch_id == batch_id:
                        setattr(r, field, new_value)
                        logger.warning("篡改 Leader 记录: %s.%s", batch_id, field)
                        return True
        return False

    def delete_record(self, batch_id: str) -> bool:
        for n in self.nodes:
            if n.is_honest:
                for i, r in enumerate(n._records):
                    if r.batch_id == batch_id:
                        n._records.pop(i)
                        logger.warning("删除 Leader 记录: %s", batch_id)
                        return True
        return False

    def inject_record(self, record: AuditRecord):
        for n in self.nodes:
            if n.is_honest:
                n._records.append(record)
        logger.info("跨节点注入记录: %s", record.batch_id)

    @property
    def consensus_logs(self) -> list[dict]:
        return self._consensus_log[:]


# ======================================================================
#  全局共享共识网络（单例）
# ======================================================================

_shared_network: MockConsensusNetwork | None = None


def _get_shared_network() -> MockConsensusNetwork:
    """获取或创建共享的 PBFT 共识网络。"""
    global _shared_network
    if _shared_network is None:
        from src.config import CONSENSUS_NODE_COUNT
        # 6 节点: f=1 (f ≤ (6-1)/3 = 1)
        fault = 1
        _shared_network = MockConsensusNetwork(
            num_nodes=CONSENSUS_NODE_COUNT, fault_nodes=fault)
    return _shared_network


def reset_shared_network():
    """重置共享共识网络（测试用）。"""
    global _shared_network
    _shared_network = None


# ======================================================================
# MockBCOS — 外部统一接口（委托给共享共识网络）
# ======================================================================

class MockBCOS:
    """模拟 FISCO BCOS — 内部委托给 PBFT 共识网络。

    所有 MockBCOS 实例共享同一个底层共识网络，
    因此无论从哪里调用，都操作同一个 4 节点联盟链。
    """

    def __init__(self, ledger_path: str | None = None):
        self._network = _get_shared_network()
        # 保留 ledger_path 用于兼容但不影响共识网络
        self._ledger_path = ledger_path or DEBUG_LEDGER_FILE

    # ------------------------------------------------------------------
    # 核心合约接口（委托给共识网络）
    # ------------------------------------------------------------------

    def record_audit(self, batch_id: str, merkle_root: str,
                     signature: str, signer_key_fp: str,
                     timestamp: str, log_count: int) -> str:
        return self._network.record_audit(
            batch_id, merkle_root, signature,
            signer_key_fp, timestamp, log_count)

    def verify_chain_integrity(self) -> ChainIntegrityResult:
        return self._network.verify_chain_integrity()

    def verify_record(self, batch_id: str, merkle_root: str) -> bool:
        return self._network.verify_record(batch_id, merkle_root)

    def get_chain_info(self) -> ChainInfo:
        return self._network.get_chain_info()

    def query_by_batch_id(self, batch_id: str) -> AuditRecord | None:
        return self._network.query_by_batch_id(batch_id)

    def query_by_time_range(self, start_time: str,
                            end_time: str) -> list[AuditRecord]:
        return self._network.query_by_time_range(start_time, end_time)

    # ------------------------------------------------------------------
    # 联盟链专用（PBFT / 拜占庭）
    # ------------------------------------------------------------------

    @property
    def consensus_network(self) -> MockConsensusNetwork:
        return self._network

    def get_consensus_status(self) -> dict:
        return self._network.get_network_status()

    def cross_verify(self) -> dict:
        return self._network.cross_verify()

    def simulate_byzantine_attack(self, node_index: int = -1) -> dict:
        return self._network.simulate_byzantine_attack(node_index)

    @property
    def consensus_logs(self) -> list[dict]:
        return self._network.consensus_logs

    # ------------------------------------------------------------------
    # Debug 工具
    # ------------------------------------------------------------------

    def reset_ledger(self):
        self._network.reset_ledger()

    def inject_record(self, record: AuditRecord):
        self._network.inject_record(record)

    def tamper_record(self, batch_id: str, field: str,
                      new_value: str) -> bool:
        return self._network.tamper_record(batch_id, field, new_value)

    def delete_record(self, batch_id: str) -> bool:
        return self._network.delete_record(batch_id)

    def dump_ledger(self) -> dict:
        leader = self._network._leader()
        return {
            "type": "PBFT_consensus_network",
            "latest_batch_id": (leader._records[-1].batch_id
                               if leader._records else None),
            "records": [r.to_dict() for r in leader._records],
            "network_status": self._network.get_network_status(),
        }


# ======================================================================
# 工厂函数
# ======================================================================

def create_consensus_network(num_nodes: int = 4,
                             fault_nodes: int = 1) -> MockConsensusNetwork:
    return MockConsensusNetwork(num_nodes=num_nodes, fault_nodes=fault_nodes)
