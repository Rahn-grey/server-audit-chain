"""
基于联盟链的服务器操作审计系统 - Python智能合约

本合约实现了链式审计存证的核心逻辑：
- record_audit:   链式记录存储，自动计算哈希指针
- verify_chain:   整链完整性验证
- verify_record:  单记录存在性验证
- get_chain_info: 链摘要信息查询
- query_by_batch_id:  按批次ID查询
- query_by_time_range: 按时间范围查询

区块链原理体现：
1. 链式结构：每条记录包含prev_hash指向上一记录的record_hash
2. 不可篡改性：修改历史记录将导致后续哈希全部断裂
3. 创世记录：prev_hash = "0"*64 标志着链的起点

注意：本合约在Debug模式下由MockBCOS直接模拟执行；
在生产模式下需部署至FISCO BCOS 3.x Python合约环境。
"""

import hashlib

GENESIS_PREV_HASH = "0" * 64


class AuditLedger:
    """审计存证合约 - 链式存证核心逻辑。"""

    def __init__(self):
        self._records = {}
        self._latest_batch_id = None
        self._order = []

    # ------------------------------------------------------------------
    # 公开查询函数
    # ------------------------------------------------------------------

    def total_records(self) -> int:
        """返回存证记录总数。"""
        return len(self._records)

    def latest_batch_id(self) -> str:
        """返回最新批次ID。"""
        return self._latest_batch_id

    # ------------------------------------------------------------------
    # 核心函数
    # ------------------------------------------------------------------

    def record_audit(self, batch_id: str, merkle_root: str,
                     signature: str, signer_key_fp: str,
                     timestamp: str, log_count: int) -> str:
        """记录一条审计存证，构建链式结构。

        参数:
            batch_id:      批次唯一标识
            merkle_root:   本批次Merkle根哈希（64字符十六进制）
            signature:     Ed25519签名（Base64编码）
            signer_key_fp: 签名公钥SHA-256指纹
            timestamp:     ISO 8601时间戳
            log_count:     本批次日志条数

        返回:
            record_hash: 本条记录的链式哈希

        逻辑:
            1. 校验batch_id是否已存在，存在则拒绝。
            2. 获取最新记录的record_hash作为prev_hash。
               - 若为第一条，prev_hash = 64个"0"。
            3. 计算 record_hash = SHA256(prev_hash + batch_id +
               merkle_root + signature + timestamp)。
            4. 将记录存入状态变量。
            5. 更新latest_batch_id指针。
        """
        if batch_id in self._records:
            raise ValueError(f"batch_id '{batch_id}' already exists")

        prev_hash = (
            self._records[self._latest_batch_id]["record_hash"]
            if self._latest_batch_id
            else GENESIS_PREV_HASH
        )

        raw = (prev_hash + batch_id + merkle_root +
               signature + timestamp).encode()
        record_hash = hashlib.sha256(raw).hexdigest()

        self._records[batch_id] = {
            "batch_id": batch_id,
            "merkle_root": merkle_root,
            "prev_hash": prev_hash,
            "record_hash": record_hash,
            "signature": signature,
            "signer_key_fp": signer_key_fp,
            "timestamp": timestamp,
            "log_count": log_count,
        }
        self._order.append(batch_id)
        self._latest_batch_id = batch_id

        return record_hash

    def verify_chain_integrity(self) -> dict:
        """验证整条审计链的完整性。

        遍历所有记录，校验：
        1. 创世记录prev_hash是否为全零。
        2. 逐条重算record_hash与实际存储值比对。
        3. 校验上一条的record_hash是否等于本条prev_hash。
        4. 发现不匹配立即返回断裂位置。

        返回:
            {
                "is_valid": bool,
                "total_records": int,
                "broken_position": int,   # -1表示无断裂
                "first_batch_id": str | None,
                "last_batch_id": str | None,
            }
        """
        total = len(self._order)
        if total == 0:
            return {
                "is_valid": True,
                "total_records": 0,
                "broken_position": -1,
                "first_batch_id": None,
                "last_batch_id": None,
            }

        first = self._records[self._order[0]]
        last = self._records[self._order[-1]]

        for i, batch_id in enumerate(self._order):
            record = self._records[batch_id]

            # (1) 校验prev_hash连续性
            expected_prev = (
                GENESIS_PREV_HASH
                if i == 0
                else self._records[self._order[i - 1]]["record_hash"]
            )
            if record["prev_hash"] != expected_prev:
                return {
                    "is_valid": False,
                    "total_records": total,
                    "broken_position": i,
                    "first_batch_id": first["batch_id"],
                    "last_batch_id": last["batch_id"],
                }

            # (2) 重算record_hash
            raw = (record["prev_hash"] + record["batch_id"] +
                   record["merkle_root"] + record["signature"] +
                   record["timestamp"]).encode()
            expected_hash = hashlib.sha256(raw).hexdigest()
            if record["record_hash"] != expected_hash:
                return {
                    "is_valid": False,
                    "total_records": total,
                    "broken_position": i,
                    "first_batch_id": first["batch_id"],
                    "last_batch_id": last["batch_id"],
                }

        return {
            "is_valid": True,
            "total_records": total,
            "broken_position": -1,
            "first_batch_id": first["batch_id"],
            "last_batch_id": last["batch_id"],
        }

    def verify_record(self, batch_id: str, merkle_root: str) -> bool:
        """验证指定批次记录是否存在且Merkle Root一致。

        返回:
            True表示验证通过。
        """
        record = self._records.get(batch_id)
        if record is None:
            return False
        return record["merkle_root"] == merkle_root

    def get_chain_info(self) -> dict:
        """获取审计链摘要信息。

        返回:
            {
                "total_records": int,
                "genesis_batch_id": str | None,
                "genesis_time": str | None,
                "latest_batch_id": str | None,
                "latest_time": str | None,
                "latest_record_hash": str | None,
            }
        """
        if not self._order:
            return {
                "total_records": 0,
                "genesis_batch_id": None,
                "genesis_time": None,
                "latest_batch_id": None,
                "latest_time": None,
                "latest_record_hash": None,
            }

        first = self._records[self._order[0]]
        last = self._records[self._order[-1]]

        return {
            "total_records": len(self._order),
            "genesis_batch_id": first["batch_id"],
            "genesis_time": first["timestamp"],
            "latest_batch_id": last["batch_id"],
            "latest_time": last["timestamp"],
            "latest_record_hash": last["record_hash"],
        }

    def query_by_batch_id(self, batch_id: str) -> dict | None:
        """按批次ID查询存证记录详情。"""
        return self._records.get(batch_id)

    def query_by_time_range(self, start_time: str,
                            end_time: str) -> list[dict]:
        """按时间范围查询存证记录。

        参数:
            start_time: 起始时间（ISO 8601字符串，按字典序比较）。
            end_time:   结束时间（ISO 8601字符串）。

        返回:
            匹配时间范围的记录列表，按时间升序排列。
        """
        results = []
        for batch_id in self._order:
            record = self._records[batch_id]
            if start_time <= record["timestamp"] <= end_time:
                results.append(record)
        return results


# ======================================================================
# AuditLedger ABI — 与 AuditLedger.sol 对应的合约 ABI 定义
# ======================================================================

AuditLedgerABI = {
    "contract_name": "AuditLedger",
    "contract_version": "1.0.0",
    "abi": [
        {"type": "event", "name": "RecordAudited", "inputs": [
            {"name": "batchId", "type": "string", "indexed": True},
            {"name": "recordHash", "type": "string", "indexed": False},
            {"name": "timestamp", "type": "string", "indexed": False},
        ], "anonymous": False},
        {"type": "event", "name": "ChainVerified", "inputs": [
            {"name": "isValid", "type": "bool", "indexed": False},
            {"name": "totalRecords", "type": "uint256", "indexed": False},
        ], "anonymous": False},
        {"type": "function", "name": "recordAudit",
         "inputs": [
             {"name": "batchId", "type": "string"},
             {"name": "merkleRoot", "type": "string"},
             {"name": "signature", "type": "string"},
             {"name": "signerKeyFp", "type": "string"},
             {"name": "timestamp", "type": "string"},
             {"name": "logCount", "type": "uint256"},
         ],
         "outputs": [{"name": "recordHash", "type": "string"}],
         "stateMutability": "nonpayable"},
        {"type": "function", "name": "totalRecords",
         "inputs": [],
         "outputs": [{"name": "", "type": "uint256"}],
         "stateMutability": "view"},
        {"type": "function", "name": "latestBatchId",
         "inputs": [],
         "outputs": [{"name": "", "type": "string"}],
         "stateMutability": "view"},
        {"type": "function", "name": "queryByBatchId",
         "inputs": [{"name": "batchId", "type": "string"}],
         "outputs": [
             {"name": "batchId", "type": "string"},
             {"name": "merkleRoot", "type": "string"},
             {"name": "prevHash", "type": "string"},
             {"name": "recordHash", "type": "string"},
             {"name": "signature", "type": "string"},
             {"name": "signerKeyFp", "type": "string"},
             {"name": "timestamp", "type": "string"},
             {"name": "logCount", "type": "uint256"},
         ],
         "stateMutability": "view"},
        {"type": "function", "name": "verifyRecord",
         "inputs": [
             {"name": "batchId", "type": "string"},
             {"name": "merkleRoot", "type": "string"},
         ],
         "outputs": [{"name": "", "type": "bool"}],
         "stateMutability": "view"},
        {"type": "function", "name": "verifyChainIntegrity",
         "inputs": [],
         "outputs": [
             {"name": "isValid", "type": "bool"},
             {"name": "totalRecords", "type": "uint256"},
             {"name": "brokenPosition", "type": "int256"},
             {"name": "genesisBatchId", "type": "string"},
             {"name": "latestBatchId", "type": "string"},
         ],
         "stateMutability": "view"},
        {"type": "function", "name": "getChainInfo",
         "inputs": [],
         "outputs": [
             {"name": "totalRecords", "type": "uint256"},
             {"name": "genesisBatchId", "type": "string"},
             {"name": "genesisTime", "type": "string"},
             {"name": "latestBatchId", "type": "string"},
             {"name": "latestTime", "type": "string"},
             {"name": "latestRecordHash", "type": "string"},
         ],
         "stateMutability": "view"},
        {"type": "function", "name": "queryByTimeRange",
         "inputs": [
             {"name": "startTime", "type": "string"},
             {"name": "endTime", "type": "string"},
         ],
         "outputs": [
             {"name": "batchIds", "type": "string[]"},
             {"name": "merkleRoots", "type": "string[]"},
             {"name": "recordHashes", "type": "string[]"},
             {"name": "timestamps", "type": "string[]"},
             {"name": "logCounts", "type": "uint256[]"},
         ],
         "stateMutability": "view"},
    ],
    "source_path": "bcos/contract/AuditLedger.sol",
}
