"""MockBCOS 节点 HTTP RPC 服务。

每个 MockBCOS 节点包装为独立的 Flask HTTP 服务，
部署为独立 Docker 容器时相当于联盟链的一个共识节点。

用法:
    python -m src.debug.mock_node_server --node-id node_0 --port 6000 --peers node_1:6001,node_2:6002,node_3:6003

端点:
    POST /vote        — PBFT Prepare 投票
    POST /commit      — PBFT Commit 提交
    GET  /query/<id>  — 查询记录
    GET  /integrity   — 链完整性验证
    GET  /status      — 节点状态
"""

import hashlib
import json
import logging
import random
import sys
from pathlib import Path

from flask import Flask, jsonify, request

logger = logging.getLogger("mock-node")

GENESIS_PREV_HASH = "0" * 64

app = Flask(__name__)

# 节点状态
_node_id = "node_0"
_is_honest = True
_records: list[dict] = []
_peers: list[str] = []


# ====================================================================
# 核心逻辑
# ====================================================================

def _compute_hash(prev_hash, batch_id, merkle_root, signature, timestamp):
    raw = (prev_hash + batch_id + merkle_root + signature + timestamp).encode()
    return hashlib.sha256(raw).hexdigest()


# ====================================================================
# RPC 端点
# ====================================================================

@app.route("/vote", methods=["POST"])
def vote():
    """PBFT Prepare: 节点对存证提议投票。"""
    data = request.get_json(force=True)
    batch_id = data["batch_id"]
    merkle_root = data["merkle_root"]
    signature = data["signature"]
    signer_key_fp = data.get("signer_key_fp", "")
    timestamp = data["timestamp"]
    log_count = data.get("log_count", 0)

    # 校验重复
    for r in _records:
        if r["batch_id"] == batch_id:
            return jsonify({"vote": "reject", "reason": "batch_id_duplicate"})

    prev_hash = _records[-1]["record_hash"] if _records else GENESIS_PREV_HASH
    record_hash = _compute_hash(prev_hash, batch_id, merkle_root, signature, timestamp)

    if _is_honest:
        return jsonify({"vote": "agree", "record_hash": record_hash, "prev_hash": prev_hash})
    else:
        if random.random() < 0.5:
            logger.warning("[BYZANTINE] %s 返回篡改 hash", _node_id)
            return jsonify({"vote": "agree", "record_hash": hashlib.sha256(b"EVIL").hexdigest()})
        else:
            return jsonify({"vote": "reject", "reason": "byzantine_refuse"})


@app.route("/commit", methods=["POST"])
def commit():
    """PBFT Commit: 共识达成后写入账本。"""
    data = request.get_json(force=True)
    record = {
        "batch_id": data["batch_id"],
        "merkle_root": data["merkle_root"],
        "prev_hash": data["prev_hash"],
        "record_hash": data["record_hash"],
        "signature": data["signature"],
        "signer_key_fp": data.get("signer_key_fp", ""),
        "timestamp": data["timestamp"],
        "log_count": data.get("log_count", 0),
        "tx_hash": data.get("tx_hash", ""),
    }
    _records.append(record)
    logger.info("[%s] 区块已提交: batch_id=%s, hash=%s", _node_id, record["batch_id"], record["record_hash"][:16])
    return jsonify({"status": "ok", "node_id": _node_id})


@app.route("/query/<batch_id>", methods=["GET"])
def query(batch_id):
    for r in _records:
        if r["batch_id"] == batch_id:
            return jsonify(r)
    return jsonify(None)


@app.route("/integrity", methods=["GET"])
def integrity():
    for i, r in enumerate(_records):
        expected_prev = GENESIS_PREV_HASH if i == 0 else _records[i - 1]["record_hash"]
        if r["prev_hash"] != expected_prev:
            return jsonify({"is_valid": False, "broken_position": i, "total": len(_records)})
        expected = _compute_hash(r["prev_hash"], r["batch_id"], r["merkle_root"], r["signature"], r["timestamp"])
        if r["record_hash"] != expected:
            return jsonify({"is_valid": False, "broken_position": i, "total": len(_records)})
    return jsonify({"is_valid": True, "broken_position": -1, "total": len(_records)})


@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "node_id": _node_id,
        "type": "honest" if _is_honest else "byzantine",
        "record_count": len(_records),
        "latest_hash": _records[-1]["record_hash"][:16] if _records else "N/A",
    })


@app.route("/tamper", methods=["POST"])
def tamper():
    """模拟拜占庭篡改：修改本节点最后一条记录的 merkle_root。"""
    data = request.get_json(force=True)
    batch_id = data.get("batch_id")
    new_root = data.get("new_merkle_root", hashlib.sha256(b"BYZANTINE").hexdigest())
    for r in _records:
        if r["batch_id"] == batch_id:
            old = r["merkle_root"]
            r["merkle_root"] = new_root
            logger.warning("[BYZANTINE] %s 篡改 batch_id=%s: %s... → %s...", _node_id, batch_id, old[:16], new_root[:16])
            return jsonify({"success": True, "old_merkle_root": old, "new_merkle_root": new_root})
    return jsonify({"success": False, "message": "batch_id not found"})


@app.route("/reset", methods=["POST"])
def reset():
    global _records
    _records = []
    return jsonify({"status": "ok"})


# ====================================================================
# 启动
# ====================================================================

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-id", default="node_0")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--peers", default="")
    parser.add_argument("--byzantine", action="store_true")
    args = parser.parse_args()

    _node_id = args.node_id
    _is_honest = not args.byzantine
    if args.peers:
        _peers = args.peers.split(",")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    logger.info("MockBCOS 节点启动: id=%s, port=%d, honest=%s", _node_id, args.port, _is_honest)
    app.run(host="0.0.0.0", port=args.port, debug=False)
