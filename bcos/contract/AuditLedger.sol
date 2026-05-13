// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title 基于联盟链的服务器操作审计 - 审计存证合约
/// @notice 链式存证核心逻辑，与 Python AuditLedger 和 MockBCOS 逻辑完全一致
/// @dev 部署至 FISCO BCOS 3.x 网络
///
/// 区块链原理体现:
/// 1. 链式结构: 每条记录包含 prevHash 指向上一条记录的 recordHash
/// 2. 不可篡改性: 修改历史记录将导致后续哈希全部断裂
/// 3. 创世记录: prevHash = 64 个 "0" 标记链的起点
contract AuditLedger {
    /* ----------------------------------------------------------------- */
    /*  常量                                                              */
    /* ----------------------------------------------------------------- */

    /// @notice 创世记录的前驱哈希，64个"0"
    string private constant GENESIS_PREV_HASH =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /* ----------------------------------------------------------------- */
    /*  类型定义                                                          */
    /* ----------------------------------------------------------------- */

    /// @notice 单条链上存证记录
    struct AuditRecord {
        string batchId;          // 批次唯一标识
        string merkleRoot;       // 本批次日志的 Merkle Root（64字符十六进制）
        string prevHash;         // 前一条记录的 recordHash
        string recordHash;       // 本条记录的链式哈希
        string signature;        // Ed25519 签名（Base64 编码）
        string signerKeyFp;      // 签名公钥 SHA-256 指纹
        string timestamp;        // ISO 8601 时间戳
        uint256 logCount;        // 本批次日志条数
    }

    /* ----------------------------------------------------------------- */
    /*  状态变量                                                          */
    /* ----------------------------------------------------------------- */

    /// @notice 按序存储的存证记录列表
    AuditRecord[] private _records;

    /// @notice batchId → 是否已存在的标记映射
    mapping(bytes32 => bool) private _exists;

    /// @notice 最新批次的 batchId
    string private _latestBatchId;

    /* ----------------------------------------------------------------- */
    /*  事件                                                              */
    /* ----------------------------------------------------------------- */

    /// @notice 成功记录审计存证时触发
    /// @param batchId 批次标识
    /// @param recordHash 本条记录的链式哈希
    /// @param timestamp 上链时间
    event RecordAudited(string indexed batchId, string recordHash, string timestamp);

    /// @notice 链完整性验证结果事件
    /// @param isValid 是否完整
    /// @param totalRecords 记录总数
    event ChainVerified(bool isValid, uint256 totalRecords);

    /* ----------------------------------------------------------------- */
    /*  内部函数 - 哈希计算                                               */
    /* ----------------------------------------------------------------- */

    /// @notice 将 bytes32 转换为 64 字符十六进制字符串
    /// @param data 32 字节数据
    /// @return 64 字符小写十六进制字符串
    function _bytes32ToHex(bytes32 data) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    /// @notice 计算 recordHash = SHA256(prevHash + batchId + merkleRoot + signature + timestamp)
    /// @dev 计算逻辑与 Python AuditLedger._compute_record_hash / MockBCOS 完全一致
    function _computeRecordHash(
        string memory prevHash,
        string memory batchId,
        string memory merkleRoot,
        string memory signature,
        string memory timestamp
    ) private pure returns (string memory) {
        bytes32 hash = sha256(
            abi.encodePacked(prevHash, batchId, merkleRoot, signature, timestamp)
        );
        return _bytes32ToHex(hash);
    }

    /* ----------------------------------------------------------------- */
    /*  公开函数 - 写操作                                                 */
    /* ----------------------------------------------------------------- */

    /// @notice 记录一条审计存证，构建链式结构
    /// @param batchId 批次唯一标识
    /// @param merkleRoot 本批次 Merkle Root（64字符十六进制）
    /// @param signature Ed25519 签名（Base64 编码）
    /// @param signerKeyFp 签名公钥 SHA-256 指纹
    /// @param timestamp ISO 8601 时间戳
    /// @param logCount 本批次日志条数
    /// @return recordHash 本条记录的链式哈希
    /// @dev 校验 batchId 唯一性，自动计算 prevHash 和 recordHash
    function recordAudit(
        string memory batchId,
        string memory merkleRoot,
        string memory signature,
        string memory signerKeyFp,
        string memory timestamp,
        uint256 logCount
    ) external returns (string memory) {
        require(bytes(batchId).length > 0, "batchId cannot be empty");
        require(bytes(merkleRoot).length == 64, "merkleRoot must be 64 chars");

        bytes32 key = keccak256(bytes(batchId));
        require(!_exists[key], "batchId already exists");
        _exists[key] = true;

        string memory prevHash = _records.length == 0
            ? GENESIS_PREV_HASH
            : _records[_records.length - 1].recordHash;

        string memory recordHash = _computeRecordHash(
            prevHash, batchId, merkleRoot, signature, timestamp
        );

        _records.push(AuditRecord({
            batchId: batchId,
            merkleRoot: merkleRoot,
            prevHash: prevHash,
            recordHash: recordHash,
            signature: signature,
            signerKeyFp: signerKeyFp,
            timestamp: timestamp,
            logCount: logCount
        }));

        _latestBatchId = batchId;

        emit RecordAudited(batchId, recordHash, timestamp);
        return recordHash;
    }

    /* ----------------------------------------------------------------- */
    /*  公开函数 - 查询                                                   */
    /* ----------------------------------------------------------------- */

    /// @notice 返回存证记录总数
    function totalRecords() external view returns (uint256) {
        return _records.length;
    }

    /// @notice 返回最新批次 ID
    function latestBatchId() external view returns (string memory) {
        return _latestBatchId;
    }

    /// @notice 按批次 ID 查询存证记录详情
    /// @param batchId 批次 ID
    /// @return 记录详情（不存在时返回空值）
    function queryByBatchId(string memory batchId)
        external
        view
        returns (AuditRecord memory)
    {
        bytes32 key = keccak256(bytes(batchId));
        if (!_exists[key]) {
            return AuditRecord("", "", "", "", "", "", "", 0);
        }
        for (uint256 i = 0; i < _records.length; i++) {
            if (keccak256(bytes(_records[i].batchId)) == key) {
                return _records[i];
            }
        }
        return AuditRecord("", "", "", "", "", "", "", 0);
    }

    /// @notice 验证指定批次记录是否存在且 Merkle Root 一致
    /// @param batchId 批次 ID
    /// @param merkleRoot 待比对的 Merkle Root
    /// @return true 表示验证通过
    function verifyRecord(string memory batchId, string memory merkleRoot)
        external
        view
        returns (bool)
    {
        bytes32 key = keccak256(bytes(batchId));
        if (!_exists[key]) {
            return false;
        }
        for (uint256 i = 0; i < _records.length; i++) {
            if (
                keccak256(bytes(_records[i].batchId)) == key &&
                keccak256(bytes(_records[i].merkleRoot)) == keccak256(bytes(merkleRoot))
            ) {
                return true;
            }
        }
        return false;
    }

    /// @notice 验证整条审计链的完整性
    /// @return isValid 链是否完整
    /// @return totalRecords 记录总数
    /// @return brokenPosition 断裂位置（-1 表示无断裂）
    /// @return genesisBatchId 创世批次 ID
    /// @return latestBatchId 最新批次 ID
    /// @dev 遍历所有记录校验:
    ///      1. 创世记录 prevHash 是否为全零
    ///      2. 逐条重算 recordHash 与实际存储值比对
    ///      3. 上一条的 recordHash 是否等于本条 prevHash
    function verifyChainIntegrity()
        external
        view
        returns (
            bool isValid,
            uint256 totalRecords_,
            int256 brokenPosition,
            string memory genesisBatchId,
            string memory latestBatchId_
        )
    {
        uint256 total = _records.length;
        if (total == 0) {
            return (true, 0, -1, "", "");
        }

        genesisBatchId = _records[0].batchId;
        latestBatchId_ = _latestBatchId;

        for (uint256 i = 0; i < total; i++) {
            AuditRecord storage record = _records[i];

            // (1) 校验 prevHash 连续性
            string memory expectedPrev = (i == 0)
                ? GENESIS_PREV_HASH
                : _records[i - 1].recordHash;
            if (
                keccak256(bytes(record.prevHash)) != keccak256(bytes(expectedPrev))
            ) {
                return (false, total, int256(i), genesisBatchId, latestBatchId_);
            }

            // (2) 重算 recordHash
            string memory expectedHash = _computeRecordHash(
                record.prevHash,
                record.batchId,
                record.merkleRoot,
                record.signature,
                record.timestamp
            );
            if (
                keccak256(bytes(record.recordHash)) != keccak256(bytes(expectedHash))
            ) {
                return (false, total, int256(i), genesisBatchId, latestBatchId_);
            }
        }

        return (true, total, -1, genesisBatchId, latestBatchId_);
    }

    /// @notice 获取审计链摘要信息
    /// @return totalRecords 记录总数
    /// @return genesisBatchId 创世批次 ID
    /// @return genesisTime 创世时间
    /// @return latestBatchId 最新批次 ID
    /// @return latestTime 最新时间
    /// @return latestRecordHash 最新 recordHash
    function getChainInfo()
        external
        view
        returns (
            uint256 totalRecords_,
            string memory genesisBatchId,
            string memory genesisTime,
            string memory latestBatchId_,
            string memory latestTime,
            string memory latestRecordHash
        )
    {
        uint256 total = _records.length;
        if (total == 0) {
            return (0, "", "", "", "", "");
        }

        AuditRecord storage genesis = _records[0];
        AuditRecord storage latest = _records[total - 1];

        return (
            total,
            genesis.batchId,
            genesis.timestamp,
            latest.batchId,
            latest.timestamp,
            latest.recordHash
        );
    }

    /// @notice 按时间范围查询存证记录（最多返回 100 条）
    /// @param startTime 起始时间（ISO 8601，按字典序比较）
    /// @param endTime 结束时间（ISO 8601）
    /// @return batchIds 匹配的批次 ID 列表
    /// @return merkleRoots 对应的 Merkle Root 列表
    /// @return recordHashes 对应的 recordHash 列表
    /// @return timestamps 对应的时间戳列表
    /// @return logCounts 对应的日志条数列表
    function queryByTimeRange(string memory startTime, string memory endTime)
        external
        view
        returns (
            string[] memory batchIds,
            string[] memory merkleRoots,
            string[] memory recordHashes,
            string[] memory timestamps,
            uint256[] memory logCounts
        )
    {
        // 先统计匹配数
        uint256 matchCount = 0;
        for (uint256 i = 0; i < _records.length; i++) {
            string memory ts = _records[i].timestamp;
            if (
                keccak256(bytes(ts)) >= keccak256(bytes(startTime)) &&
                keccak256(bytes(ts)) <= keccak256(bytes(endTime))
            ) {
                matchCount++;
            }
        }

        // 限制最大返回条数
        uint256 resultSize = matchCount > 100 ? 100 : matchCount;

        batchIds = new string[](resultSize);
        merkleRoots = new string[](resultSize);
        recordHashes = new string[](resultSize);
        timestamps = new string[](resultSize);
        logCounts = new uint256[](resultSize);

        uint256 index = 0;
        for (uint256 i = 0; i < _records.length && index < resultSize; i++) {
            string memory ts = _records[i].timestamp;
            if (
                keccak256(bytes(ts)) >= keccak256(bytes(startTime)) &&
                keccak256(bytes(ts)) <= keccak256(bytes(endTime))
            ) {
                batchIds[index] = _records[i].batchId;
                merkleRoots[index] = _records[i].merkleRoot;
                recordHashes[index] = _records[i].recordHash;
                timestamps[index] = _records[i].timestamp;
                logCounts[index] = _records[i].logCount;
                index++;
            }
        }
    }
}
