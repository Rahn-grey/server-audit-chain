"""Flask路由定义。

提供RESTful API接口：
- POST   /api/v1/audit/batch         接收批次日志，完成哈希链更新、签名、上链
- GET    /api/v1/audit/search         搜索操作日志
- POST   /api/v1/audit/verify         验证单条日志真伪
- GET    /api/v1/audit/chain/integrity 验证整条审计链完整性
- GET    /api/v1/audit/chain/info      获取审计链摘要信息
- GET    /api/v1/audit/record/<batch_id> 查询链上存证记录
"""

import base64
import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, Flask, jsonify, render_template, request

from src.chain.hash_chain import HashChain
from src.crypto.key_manager import (
    generate_key_pair,
    get_public_key_fingerprint,
    load_private_key,
)
from src.crypto.signer import sign
from src.ledger.contract import AuditContract
from src.merkle.tree import MerkleTree
from src.storage.query import AuditQuery
from src.storage import ESClient
from src.alert.engine import AlertEngine

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api/v1/audit")

# 全局实例（生产环境应通过依赖注入初始化）
_contract = AuditContract()
_query = AuditQuery()
_es = ESClient()
_hash_chain = None   # 应用启动时初始化
_alert_engine = None  # 应用启动时初始化


def init_app(app: Flask, private_key_path: str | None = None,
             hash_chain_path: str | None = None):
    """初始化API应用。

    Args:
        app: Flask应用实例。
        private_key_path: 签名私钥路径，不指定则自动生成。
        hash_chain_path: 哈希链状态持久化路径。
    """
    global _hash_chain

    _hash_chain = HashChain(state_path=hash_chain_path)

    # 密钥初始化
    global _private_key, _public_key_fp
    if private_key_path:
        _private_key = load_private_key(private_key_path)
    else:
        _private_key, public_key = generate_key_pair()
        _public_key_fp = get_public_key_fingerprint(public_key)
        logger.info("自动生成签名密钥对，公钥指纹: %s", _public_key_fp)

    # 告警引擎初始化（SMTP未配置时静默跳过）
    global _alert_engine
    try:
        _alert_engine = AlertEngine()
        logger.info("告警引擎已初始化")
    except Exception as e:
        logger.warning("告警引擎初始化跳过: %s", e)
        _alert_engine = None

    app.register_blueprint(api_bp)
    logger.info("API路由已注册")


@api_bp.route("/batch", methods=["POST"])
def submit_batch():
    """接收批次日志，完成哈希链更新、签名、上链。"""
    try:
        data = request.get_json(force=True)
        batch_id = data.get("batch_id")
        logs = data.get("logs", [])

        if not batch_id:
            return jsonify({"error": "batch_id is required"}), 400
        if not logs:
            return jsonify({"error": "logs is required"}), 400
        if len(logs) > 10000:
            return jsonify({"error": "单批次日志数不能超过10000"}), 400

        # 1. 构建Merkle树
        tree = MerkleTree(logs)
        merkle_root = tree.get_root()

        # 2. 哈希链追加
        chain_hash = _hash_chain.add_batch(batch_id, merkle_root)

        # 3. Ed25519签名
        data_to_sign = chain_hash.encode()
        signature = sign(data_to_sign, _private_key)
        signature_b64 = base64.b64encode(signature).decode()

        # 4. 上链存证
        timestamp = datetime.now(timezone.utc).isoformat()
        record_hash = _contract.submit_audit_record(
            batch_id=batch_id,
            merkle_root=merkle_root,
            signature=signature_b64,
            signer_key_fp=_public_key_fp,
            timestamp=timestamp,
            log_count=len(logs),
        )

        # 5. 存储日志原文到ES
        _es.bulk_index(logs)

        # 6. 告警检查（高危命令触发邮件告警）
        if _alert_engine:
            try:
                for log in logs:
                    log.setdefault("batch_id", batch_id)
                _alert_engine.check_batch_and_alert(logs)
            except Exception as e:
                logger.warning("告警检查异常: %s", e)

        return jsonify({
            "batch_id": batch_id,
            "merkle_root": merkle_root,
            "chain_hash": chain_hash,
            "record_hash": record_hash,
            "log_count": len(logs),
            "timestamp": timestamp,
        }), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        logger.exception("批次提交失败")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/search", methods=["GET"])
def search_logs():
    """搜索操作日志。"""
    operator = request.args.get("operator")
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")
    keyword = request.args.get("keyword")
    page = request.args.get("page", 1, type=int)
    size = request.args.get("size", 50, type=int)

    if size > 100:
        size = 100

    result = _query.search_logs(
        operator=operator, start_time=start_time,
        end_time=end_time, keyword=keyword,
        page=page, size=size,
    )
    return jsonify(result)


@api_bp.route("/verify", methods=["POST"])
def verify_log():
    """验证单条日志真伪。"""
    data = request.get_json(force=True)
    log_id = data.get("log_id")
    public_key_path = data.get("public_key_path")

    if not log_id:
        return jsonify({"error": "log_id is required"}), 400

    result = _query.verify_log(log_id, public_key_path)
    status = 200 if result.get("verified") else 200  # 验证失败也返回200
    return jsonify(result), status


@api_bp.route("/chain/integrity", methods=["GET"])
def chain_integrity():
    """验证整条审计链完整性。"""
    result = _query.verify_chain_integrity()
    return jsonify(result)


@api_bp.route("/chain/info", methods=["GET"])
def chain_info():
    """获取审计链摘要信息。"""
    result = _query.get_chain_info()
    return jsonify(result)


@api_bp.route("/record/<batch_id>", methods=["GET"])
def query_record(batch_id):
    """查询链上存证记录详情。"""
    record = _query.get_record(batch_id)
    if record is None:
        return jsonify({"error": "记录不存在"}), 404
    return jsonify(record)


# ==================================================================
# 联盟链 PBFT 共识专用端点 (debug / 生产均可)
# ==================================================================

@api_bp.route("/chain/consensus", methods=["GET"])
def consensus_status():
    """获取联盟链 PBFT 共识网络状态。

    在 debug 模式下返回完整的 4 节点 PBFT 投票状态；
    生产模式下通过 FISCO BCOS 查询节点列表。
    """
    try:
        status = _contract.get_consensus_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e),
                       "message": "共识状态查询失败，请确认运行模式"})


@api_bp.route("/chain/cross-verify", methods=["GET"])
def cross_verify():
    """跨节点账本一致性验证。

    比对联盟链所有节点的账本，检测拜占庭节点篡改。
    """
    try:
        report = _contract.get_cross_verify()
        status_code = 200 if report.get("consensus_ok") else 409
        return jsonify(report), status_code
    except Exception as e:
        return jsonify({"error": str(e)})


@api_bp.route("/chain/attack", methods=["POST"])
def simulate_attack():
    """模拟拜占庭节点攻击（仅debug模式）。

    调用后指定拜占庭节点篡改本地账本数据。
    再调用 GET /chain/cross-verify 可观察到检出结果。
    """
    try:
        result = _contract.simulate_attack()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})


def create_app(private_key_path: str | None = None,
               hash_chain_path: str | None = None) -> Flask:
    """创建并初始化Flask应用。"""
    app = Flask(__name__)
    init_app(app, private_key_path, hash_chain_path)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/verify")
    def verify_page():
        return render_template("verify.html")

    return app
