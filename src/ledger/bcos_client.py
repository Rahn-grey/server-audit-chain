from __future__ import annotations
"""FISCO BCOS Python SDK封装 — 生产模式区块链客户端。

提供两种连接方式:
    1. SDK模式:  使用 FISCO BCOS Python SDK (pip install bcos3sdk)
    2. HTTP模式:  直接 JSON-RPC HTTP 调用 (零依赖，仅需 requests)

Debug模式下由 MockBCOS 替代（见 src/storage/__init__.py）。

环境准备:
    # 启动 FISCO BCOS 四节点网络
    docker-compose --profile production up -d

    # 编译合约 (需要 solc 或 Remix IDE)
    solc --abi --bin bcos/contract/AuditLedger.sol -o bcos/contract/build/

    # 部署合约获取地址
    python scripts/deploy_contract.py
    # 输出: 合约地址 = 0x...

    # 设置环境变量
    export AUDIT_SYSTEM_MODE=production
    export BCOS_CONTRACT_ADDR=0x...
"""

import json
import logging
import urllib.request
import urllib.error
from pathlib import Path

from src.config import BCOS_CONFIG

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 先尝试导入 SDK，不可用时回退到 HTTP JSON-RPC
# ---------------------------------------------------------------------------
_SDK_AVAILABLE = False
_SDK_CLIENT = None
_SDK_CONFIG = None

try:
    from bcos3sdk.bcos3client import Bcos3Client as _Bcos3Client
    from bcos3sdk.bcos3client import Bcos3Config as _Bcos3Config
    _SDK_AVAILABLE = True
    _SDK_CLIENT = _Bcos3Client
    _SDK_CONFIG = _Bcos3Config
    logger.info("FISCO BCOS Python SDK 已加载 (bcos3sdk)")
except ImportError:
    try:
        from client.bcosclient import BcosClient as _BcosClient
        _SDK_AVAILABLE = True
        _SDK_CLIENT = _BcosClient
        logger.info("FISCO BCOS Python SDK 已加载 (client-sdk-python)")
    except ImportError:
        logger.info("Python SDK 未安装，使用 HTTP JSON-RPC 模式")
        logger.info("安装 SDK: pip install bcos3sdk  或  pip install client-sdk-python")


# ====================================================================
# BCOSClient
# ====================================================================

class BCOSClient:
    """FISCO BCOS 客户端 — SDK优先，HTTP回退。

    生产模式下使用。Debug 模式下由 src/storage/__init__.py 自动切换为 MockBCOS。
    """

    def __init__(self, config: dict | None = None):
        self.config = config or BCOS_CONFIG
        self._connected = False
        self._client = None          # SDK 客户端实例
        self._contract_addr = ""     # 已部署合约地址
        self._contract_abi = None    # 合约 ABI
        self._group_id = 1           # FISCO BCOS 群组ID

    # ------------------------------------------------------------------
    # 连接管理
    # ------------------------------------------------------------------

    def connect(self):
        """建立与 FISCO BCOS 节点的连接。"""
        endpoint = self.config.get("endpoint", "127.0.0.1:20200")
        logger.info("连接 FISCO BCOS 节点: %s", endpoint)

        host, _, port_str = endpoint.partition(":")
        port = int(port_str) if port_str else 20200

        if _SDK_AVAILABLE:
            self._connect_sdk(host, port)
        else:
            self._connect_http(host, port)

        self._connected = True
        logger.info("FISCO BCOS 连接成功")

    def _connect_sdk(self, host: str, port: int):
        """通过 Python SDK 连接。"""
        if _SDK_CONFIG is not None:
            cfg = _SDK_CONFIG()
            cfg.set_connection_config(endpoint=host, port=port)
            self._client = _SDK_CLIENT(cfg)
        else:
            self._client = _SDK_CLIENT()
            self._client.connect(host, port)

    def _connect_http(self, host: str, port: int):
        """HTTP JSON-RPC 模式 — 无 SDK 依赖。"""
        self._rpc_url = f"http://{host}:{port}"
        # 测试连接
        try:
            resp = self._rpc_call("getBlockNumber", [self._group_id])
            logger.debug("BCOS 当前块高: %s", resp.get("result", "N/A"))
        except Exception as e:
            logger.warning("BCOS 连接测试失败: %s (节点可能未启动)", e)

    def disconnect(self):
        if self._connected:
            logger.info("断开 FISCO BCOS 连接")
            self._connected = False

    # ------------------------------------------------------------------
    # 合约加载
    # ------------------------------------------------------------------

    def load_contract(self, abi_path: str | None = None,
                       contract_address: str | None = None):
        """加载 AuditLedger 合约的 ABI 和地址。

        Args:
            abi_path: ABI 文件路径 (不指定则用内建 AuditLedgerABI)。
            contract_address: 已部署的合约地址 (不指定则用环境变量)。
        """
        if abi_path:
            with open(abi_path) as f:
                abi_data = json.load(f)
            abi = abi_data if isinstance(abi_data, list) else abi_data.get("abi", [])
        else:
            from bcos.contract.audit_ledger import AuditLedgerABI
            abi = AuditLedgerABI["abi"]

        self._contract_abi = abi
        self._contract_addr = contract_address or self.config.get(
            "contract_address", ""
        )

        if not self._contract_addr:
            logger.warning("合约地址未配置 — 请设置 BCOS_CONTRACT_ADDR")
        else:
            logger.info("合约已加载: address=%s, methods=%d",
                       self._contract_addr, len([f for f in abi if f.get("type") == "function"]))

    # ------------------------------------------------------------------
    # 核心: 发送交易 (写操作)
    # ------------------------------------------------------------------

    def send_transaction(self, func_name: str, args: list) -> dict:
        """发送交易到链上，调用 AuditLedger 合约函数。

        对应 Solidity 合约中的 nonpayable 函数: recordAudit

        Args:
            func_name: 函数名，如 "recordAudit"。
            args: 参数列表，与 Solidity 函数的参数顺序一致。

        Returns:
            {"tx_hash": str, "status": int, "block_number": int}
        """
        if not self._connected:
            raise RuntimeError("未连接到 BCOS 节点")
        if not self._contract_addr:
            raise RuntimeError("合约地址未配置")

        logger.info("发送交易: %s, args=%s", func_name, args)

        if _SDK_AVAILABLE and self._client:
            return self._send_tx_sdk(func_name, args)
        else:
            return self._send_tx_http(func_name, args)

    def _send_tx_sdk(self, func_name: str, args: list) -> dict:
        """通过 SDK 发送交易。"""
        try:
            receipt = self._client.send_raw_transaction(
                self._group_id,
                "AuditLedger",
                self._contract_addr,
                json.dumps(self._contract_abi),
                func_name,
                args,
            )
            return {
                "tx_hash": receipt.get("transactionHash", ""),
                "status": receipt.get("status", 0),
                "block_number": receipt.get("blockNumber", 0),
            }
        except Exception as e:
            logger.error("SDK交易失败: %s", e)
            raise

    def _send_tx_http(self, func_name: str, args: list) -> dict:
        """通过 HTTP JSON-RPC 发送交易。

        FISCO BCOS 3.x 的 RPC 接口 sendTransaction 需要已签名的交易数据。
        完整实现需要:
        1. 加载节点私钥
        2. 构造 + 签名交易 (包括 nonce, chainId, groupId 等)
        3. 发送签名后的交易

        此处为骨架 — 部署时需配合 SDK 或手动签名。
        """
        # 查找函数 ABI 条目
        func_abi = None
        for entry in self._contract_abi:
            if entry.get("type") == "function" and entry.get("name") == func_name:
                func_abi = entry
                break

        if not func_abi:
            raise ValueError(f"ABI 中未找到函数: {func_name}")

        logger.info(
            "HTTP TX: func=%s, args=%s → 需 SDK 签名。"
            "安装 bcos3sdk 或 client-sdk-python 以获得完整交易支持。",
            func_name, args,
        )

        # JSON-RPC sendTransaction 骨架
        try:
            params = {
                "groupID": str(self._group_id),
                "contractAddress": self._contract_addr,
                "funcName": func_name,
                "funcParams": args,
                "abi": json.dumps(func_abi),
                "useCns": False,
            }
            resp = self._rpc_call("sendTransaction", [self._group_id, params])
            result = resp.get("result", {})
            return {
                "tx_hash": result.get("transactionHash", "0x0000"),
                "status": result.get("status", 0),
                "block_number": result.get("blockNumber", 0),
            }
        except Exception as e:
            logger.error("HTTP交易失败: %s", e)
            raise

    # ------------------------------------------------------------------
    # 核心: 合约查询 (读操作)
    # ------------------------------------------------------------------

    def call(self, func_name: str, args: list) -> dict:
        """调用合约 view 函数，不消耗 gas。

        对应 Solidity 合约中的 view 函数:
            totalRecords, latestBatchId, queryByBatchId,
            verifyRecord, verifyChainIntegrity, getChainInfo, queryByTimeRange

        Args:
            func_name: 函数名。
            args: 参数列表。

        Returns:
            合约返回的 dict。
        """
        if not self._connected:
            raise RuntimeError("未连接到 BCOS 节点")
        if not self._contract_addr:
            raise RuntimeError("合约地址未配置")

        if _SDK_AVAILABLE and self._client:
            return self._call_sdk(func_name, args)
        else:
            return self._call_http(func_name, args)

    def _call_sdk(self, func_name: str, args: list) -> dict:
        try:
            result = self._client.call(
                self._group_id,
                "AuditLedger",
                self._contract_addr,
                json.dumps(self._contract_abi),
                func_name,
                args,
            )
            return {"result": result}
        except Exception as e:
            logger.error("SDK调用失败: %s.%s → %s", self._contract_addr, func_name, e)
            raise

    def _call_http(self, func_name: str, args: list) -> dict:
        """HTTP JSON-RPC call 骨架。"""
        try:
            params = {
                "groupID": str(self._group_id),
                "contractAddress": self._contract_addr,
                "funcName": func_name,
                "funcParams": args,
            }
            resp = self._rpc_call("call", [self._group_id, params])
            return {"result": resp.get("result", "")}
        except Exception as e:
            logger.error("HTTP调用失败: %s.%s → %s", self._contract_addr, func_name, e)
            return {"result": None}

    # ==================================================================
    # AuditLedger 合约函数 — 与 MockBCOS 接口一致
    # ==================================================================

    def record_audit(self, batch_id: str, merkle_root: str,
                     signature: str, signer_key_fp: str,
                     timestamp: str, log_count: int) -> str:
        """调用 recordAudit() 上链存证。"""
        receipt = self.send_transaction("recordAudit", [
            batch_id, merkle_root, signature,
            signer_key_fp, timestamp, str(log_count),
        ])
        logger.info("上链成功: tx=%s", receipt.get("tx_hash", ""))
        # recordAudit 返回 recordHash，但由于 sendTransaction 只返回收据，
        # 实际需要从交易事件中解析。这里简化处理。
        return receipt.get("tx_hash", "")

    def verify_chain_integrity(self) -> "ChainIntegrityResult":
        result = self.call("verifyChainIntegrity", [])
        vals = result.get("result", [])
        # Solidity 返回 tuple: (isValid, totalRecords, brokenPosition,
        #                        genesisBatchId, latestBatchId)
        if isinstance(vals, (list, tuple)) and len(vals) >= 5:
            return ChainIntegrityResult(
                is_valid=vals[0],
                total_records=int(vals[1]),
                broken_position=int(vals[2]),
                first_batch_id=vals[3],
                last_batch_id=vals[4],
            )
        return ChainIntegrityResult(is_valid=True, total_records=0)

    def verify_record(self, batch_id: str, merkle_root: str) -> bool:
        result = self.call("verifyRecord", [batch_id, merkle_root])
        val = result.get("result", False)
        if isinstance(val, str):
            return val.lower() == "true"
        return bool(val)

    def get_chain_info(self) -> "ChainInfo":
        result = self.call("getChainInfo", [])
        vals = result.get("result", [])
        # Solidity 返回: (totalRecords, genesisBatchId, genesisTime,
        #                   latestBatchId, latestTime, latestRecordHash)
        if isinstance(vals, (list, tuple)) and len(vals) >= 6:
            return ChainInfo(
                total_records=int(vals[0]),
                genesis_batch_id=vals[1],
                genesis_time=vals[2],
                latest_batch_id=vals[3],
                latest_time=vals[4],
                latest_record_hash=vals[5],
            )
        return ChainInfo()

    def query_by_batch_id(self, batch_id: str) -> "AuditRecord | None":
        result = self.call("queryByBatchId", [batch_id])
        vals = result.get("result", [])
        if isinstance(vals, (list, tuple)) and len(vals) >= 8:
            return AuditRecord(
                batch_id=vals[0],
                merkle_root=vals[1],
                prev_hash=vals[2],
                record_hash=vals[3],
                signature=vals[4],
                signer_key_fp=vals[5],
                timestamp=vals[6],
                log_count=int(vals[7]),
                tx_hash="",
            )
        return None

    def query_by_time_range(self, start_time: str,
                            end_time: str) -> list["AuditRecord"]:
        result = self.call("queryByTimeRange", [start_time, end_time])
        vals = result.get("result", {})
        # Solidity 返回 5 个并行数组
        if isinstance(vals, dict):
            batch_ids = vals.get("batchIds", vals.get("0", []))
            roots = vals.get("merkleRoots", vals.get("1", []))
            hashes = vals.get("recordHashes", vals.get("2", []))
            timestamps = vals.get("timestamps", vals.get("3", []))
            counts = vals.get("logCounts", vals.get("4", []))
            return [
                AuditRecord(
                    batch_id=batch_ids[i] if i < len(batch_ids) else "",
                    merkle_root=roots[i] if i < len(roots) else "",
                    record_hash=hashes[i] if i < len(hashes) else "",
                    timestamp=timestamps[i] if i < len(timestamps) else "",
                    log_count=int(counts[i]) if i < len(counts) else 0,
                    prev_hash="", signature="", signer_key_fp="", tx_hash="",
                )
                for i in range(len(batch_ids))
            ]
        return []

    # ==================================================================
    # JSON-RPC 底层调用
    # ==================================================================

    def _rpc_call(self, method: str, params: list) -> dict:
        """发送 JSON-RPC 请求。"""
        if not hasattr(self, "_rpc_url"):
            raise RuntimeError("HTTP模式未初始化，请先 connect()")

        import uuid
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._rpc_url,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))


# ====================================================================
# 数据类 (与 MockBCOS 类型完全一致)
# ====================================================================

class AuditRecord:
    def __init__(self, batch_id="", merkle_root="", prev_hash="",
                 record_hash="", signature="", signer_key_fp="",
                 timestamp="", log_count=0, tx_hash=""):
        self.batch_id = batch_id
        self.merkle_root = merkle_root
        self.prev_hash = prev_hash
        self.record_hash = record_hash
        self.signature = signature
        self.signer_key_fp = signer_key_fp
        self.timestamp = timestamp
        self.log_count = log_count
        self.tx_hash = tx_hash

    def to_dict(self):
        return self.__dict__


class ChainIntegrityResult:
    def __init__(self, is_valid=True, total_records=0, broken_position=-1,
                 first_batch_id=None, last_batch_id=None):
        self.is_valid = is_valid
        self.total_records = total_records
        self.broken_position = broken_position
        self.first_batch_id = first_batch_id
        self.last_batch_id = last_batch_id

    def to_dict(self):
        return self.__dict__


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

    def to_dict(self):
        return self.__dict__
