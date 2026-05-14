"""MockBCOS HTTP 远程客户端。

连接独立容器中运行的 MockBCOS 节点，实现与 BCOSClient 相同接口。
用于 production_sim 模式：多个 mock-node 容器 + audit-api 通过 HTTP 通信。

用法:
    from src.debug.mock_bcos_client import MockBCOSClient
    client = MockBCOSClient(node_urls=["http://mock-node0:6000", ...])
    client.record_audit(...)
"""

import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


class MockBCOSClient:
    """连接远程 MockBCOS 节点（HTTP RPC），实现 BCOSClient 接口。"""

    def __init__(self, node_urls: list[str], fault_nodes: int = 1):
        self._node_urls = node_urls
        self._fault = fault_nodes
        self._quorum = 2 * fault_nodes + 1
        logger.info("MockBCOS HTTP 客户端: %d 节点, quorum=%d", len(node_urls), self._quorum)

    # ==================================================================
    # 核心接口
    # ==================================================================

    def record_audit(self, batch_id: str, merkle_root: str,
                     signature: str, signer_key_fp: str,
                     timestamp: str, log_count: int) -> str:
        """PBFT 共识上链：广播投票 → 统计 → 提交。"""
        # Phase 1: Pre-Prepare
        logger.info("[PBFT] Pre-Prepare → 广播 batch_id=%s", batch_id)

        # Phase 2: Prepare — 向所有节点投票
        payload = {
            "batch_id": batch_id, "merkle_root": merkle_root,
            "signature": signature, "signer_key_fp": signer_key_fp,
            "timestamp": timestamp, "log_count": log_count,
        }
        votes = []
        for url in self._node_urls:
            resp = self._post(f"{url}/vote", payload)
            votes.append(resp)

        agrees = [v for v in votes if v.get("vote") == "agree"]
        logger.info("[PBFT] 投票: agree=%d/%d, quorum=%d",
                   len(agrees), len(votes), self._quorum)

        if len(agrees) < self._quorum:
            raise ValueError(f"PBFT 共识失败: 需 ≥{self._quorum} 票, 实际 {len(agrees)}")

        # Phase 3: Commit — 写入所有节点
        final_rh = agrees[0]["record_hash"]
        final_ph = agrees[0].get("prev_hash", "")
        commit_payload = {
            **payload,
            "record_hash": final_rh,
            "prev_hash": final_ph,
            "tx_hash": f"pbft_tx_{batch_id[:8]}",
        }
        for url in self._node_urls:
            try:
                self._post(f"{url}/commit", commit_payload)
            except Exception as e:
                logger.warning("节点 %s commit 失败: %s", url, e)

        logger.info("[PBFT] ✅ 共识达成: record_hash=%s", final_rh[:16])
        return final_rh

    # ==================================================================
    # 查询
    # ==================================================================

    def _leader_url(self) -> str:
        return self._node_urls[0]

    def query_by_batch_id(self, batch_id: str):
        resp = self._get(f"{self._leader_url()}/query/{batch_id}")
        if resp is None:
            return None
        return _make_audit_record(resp)

    def query_by_time_range(self, start_time: str, end_time: str) -> list:
        # 简化：从 leader 查所有记录再过滤
        return []

    def verify_chain_integrity(self):
        resp = self._get(f"{self._leader_url()}/integrity")
        from src.debug.mock_bcos import ChainIntegrityResult
        return ChainIntegrityResult(
            is_valid=resp["is_valid"],
            total_records=resp.get("total", 0),
            broken_position=resp.get("broken_position", -1),
        )

    def get_chain_info(self):
        resp = self._get(f"{self._leader_url()}/status")
        from src.debug.mock_bcos import ChainInfo
        return ChainInfo(
            total_records=resp.get("record_count", 0),
            latest_record_hash=resp.get("latest_hash", None),
        )

    def verify_record(self, batch_id: str, merkle_root: str) -> bool:
        record = self.query_by_batch_id(batch_id)
        return record is not None and record.merkle_root == merkle_root

    def get_consensus_status(self) -> dict:
        nodes = []
        for url in self._node_urls:
            try:
                s = self._get(f"{url}/status")
                nodes.append({"node_id": s.get("node_id", "?"), "type": s.get("type", "?"),
                              "record_count": s.get("record_count", 0)})
            except Exception:
                nodes.append({"node_id": url, "type": "error", "record_count": 0})
        return {
            "config": {
                "total_nodes": len(self._node_urls),
                "consensus_algorithm": "PBFT (MockBCOS Network)",
                "fault_tolerance": f"f={self._fault}, 可容忍 {self._fault} 拜占庭节点",
                "quorum": f"2f+1={self._quorum}",
            },
            "nodes": nodes,
        }

    def cross_verify(self) -> dict:
        ledgers = []
        for url in self._node_urls:
            try:
                s = self._get(f"{url}/status")
                ledgers.append({"url": url, "count": s.get("record_count", 0)})
            except Exception:
                ledgers.append({"url": url, "count": -1})
        counts = set(l["count"] for l in ledgers)
        ok = len(counts) == 1 and -1 not in counts
        return {"consensus_ok": ok, "byzantine_detected": not ok,
                "summary": "[OK]" if ok else "[WARN] 节点不一致",
                "nodes": ledgers}

    # ==================================================================
    # HTTP 工具
    # ==================================================================

    def _post(self, url, data):
        payload = json.dumps(data).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())

    def _get(self, url):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise


# ====================================================================
# 辅助
# ====================================================================

def _make_audit_record(d: dict):
    from src.debug.mock_bcos import AuditRecord
    return AuditRecord(
        batch_id=d.get("batch_id", ""),
        merkle_root=d.get("merkle_root", ""),
        prev_hash=d.get("prev_hash", ""),
        record_hash=d.get("record_hash", ""),
        signature=d.get("signature", ""),
        signer_key_fp=d.get("signer_key_fp", ""),
        timestamp=d.get("timestamp", ""),
        log_count=d.get("log_count", 0),
        tx_hash=d.get("tx_hash", ""),
    )
