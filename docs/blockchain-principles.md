# 区块链存证原理 — 代码实现详解

> 本文档将项目代码与区块链核心原理一一对应，说明每条原理是如何在代码层面实现的。

---

## 目录

1. [链式哈希结构](#1-链式哈希结构)
2. [Merkle 树聚合](#2-merkle-树聚合)
3. [数字签名与不可抵赖](#3-数字签名与不可抵赖)
4. [不可篡改性](#4-不可篡改性)
5. [智能合约存证](#5-智能合约存证)
6. [PBFT 拜占庭容错](#6-pbft-拜占庭容错)
7. [去中心化验证](#7-去中心化验证)
8. [完整数据流回顾](#8-完整数据流回顾)

---

## 1. 链式哈希结构

### 原理

区块链的"链"本质上是哈希指针链表。每个区块（此处是批次记录）包含一个指向前一个区块的哈希值，从而形成一条从创世块到最新块的连续链条。

```
genesis                block 1                 block 2
┌────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ prev=0...0 │    │ prev=hash(gen)   │    │ prev=hash(blk1)  │
│ data       │ ←─ │ data             │ ←─ │ data             │
│ hash=H0    │    │ hash=H1          │    │ hash=H2          │
└────────────┘    └──────────────────┘    └──────────────────┘
```

### 代码实现

**文件: `src/chain/hash_chain.py`**

每条存证记录包含四个关键字段：

```python
# hash_chain.py:60-65
entry = {
    "batch_id": batch_id,
    "prev_hash": prev_hash,     # ← 指向上一条记录的 chain_hash
    "merkle_root": merkle_root,
    "chain_hash": chain_hash,   # ← 本条记录的哈希
}
```

计算新哈希时，将上一条哈希与本批 Merkle Root 拼接后做 SHA-256：

```python
# hash_chain.py:56-58
prev_hash = self._latest_hash if self._latest_hash else GENESIS_PREV_HASH  # "0"*64
raw = (prev_hash + merkle_root).encode()
chain_hash = hashlib.sha256(raw).hexdigest()
```

创世记录的 `prev_hash` 为 64 个 `"0"`，标志链的起点：

```python
# hash_chain.py:14
GENESIS_PREV_HASH = "0" * 64
```

### 链上层的链式结构

不仅仅是哈希链，链上存储的记录本身也构成链：

**文件: `bcos/contract/AuditLedger.sol`** (第 153-167 行)

```solidity
// 计算 recordHash = SHA256(prevHash + batchId + merkleRoot + signature + timestamp)
bytes32 hash = sha256(
    abi.encodePacked(prevHash, batchId, merkleRoot, signature, timestamp)
);

// ← 存入的记录包含 prevHash 指针
_records.push(AuditRecord({
    batchId: batchId,
    merkleRoot: merkleRoot,
    prevHash: prevHash,       // 指向上一条 recordHash
    recordHash: recordHash,   // 本条哈希
    ...
}));
```

所以系统中存在 **两层链式结构**：

```
哈希链层:  chain_hash[n] = SHA256(chain_hash[n-1] + merkle_root)
    ↓
合约层:    record_hash[n] = SHA256(record_hash[n-1] + batch_id + merkle_root + signature + timestamp)
```

两层链互相印证，任何一层被破坏都能被检测到。

---

## 2. Merkle 树聚合

### 原理

Merkle 树将大量数据（如一批日志）聚合为单一的 Merkle Root。验证某条日志是否属于该批次时，只需提供 Merkle 证明路径，无需提供全部日志。这大幅降低了链上存证的成本——无论一批有 1 条还是 10000 条日志，链上只存一个 64 字符的 Merkle Root。

```
           Root = SHA256(h01 + h23)
          /                       \
     h01 = SHA256(h0+h1)    h23 = SHA256(h2+h3)
      /        \              /        \
    h0         h1           h2         h3
  (log0)     (log1)       (log2)     (log3)
```

### 代码实现

**文件: `src/merkle/tree.py`**

构建 Merkle 树：

```python
# tree.py:31-44
class MerkleTree:
    def __init__(self, logs: list):
        # 1. 对每条日志做 SHA-256 得到叶子节点
        self.leaves = [hash_leaf(log) for log in logs]
        # 2. 自底向上逐层哈希得到根
        self.root = self._build(self.leaves) if self.leaves else None

    def _build(self, nodes: list[str]) -> str:
        if len(nodes) == 1:
            return nodes[0]
        next_level = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                combined = nodes[i] + nodes[i + 1]
            else:
                combined = nodes[i] + nodes[i]  # 奇数个时复制最后一个
            next_level.append(hashlib.sha256(combined.encode()).hexdigest())
        return self._build(next_level)
```

在 API 中，接收日志批次后立即构建 Merkle 树：

```python
# routes.py:84-85
tree = MerkleTree(logs)
merkle_root = tree.get_root()
```

### Merkle 证明

**文件: `src/merkle/proof.py`**

验证某条日志是否属于某个批次时，提供 Merkle 证明路径即可，不需要全量日志。这在审计员只关心某一条具体日志时非常高效。

```python
# proof.py: 核心逻辑
proof = tree.get_proof(log_index)   # 获取证明路径
result = verify_proof(proof, log, merkle_root)  # 验证
```

---

## 3. 数字签名与不可抵赖

### 原理

Ed25519 签名保证：
- **真实性**：签名只能由持有私钥的人产生
- **不可抵赖**：签名者不能否认自己签名过的数据
- **完整性**：签名数据被篡改后，验签会失败

### 代码实现

**文件: `src/crypto/signer.py`**

```python
# signer.py
def sign(data: bytes, private_key) -> bytes:
    """Ed25519 签名"""
    return private_key.sign(data)

def verify(data: bytes, signature: bytes, public_key) -> bool:
    """Ed25519 验签"""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
```

**文件: `src/api/routes.py:90-93`** — 签名的是哈希链的 chain_hash：

```python
data_to_sign = chain_hash.encode()
signature = sign(data_to_sign, _private_key)
signature_b64 = base64.b64encode(signature).decode()
```

所以链上存证的是：**"哪个签名者 在什么时间 对哪个 Merkle Root 签名"**。一旦签名上链，责任方无法抵赖。

---

## 4. 不可篡改性

### 原理

区块链的不可篡改来自哈希链的特性：**改一处，后面全断**。

```
假设原始链:
  A(prev=0) → B(prev=h(A)) → C(prev=h(B))

篡改 B 的数据后，h(B') ≠ h(B)，C 的 prev_hash 仍然是 h(B)
因此: h(C_prev) ≠ h(B') → 链断裂
```

### 代码实现

**文件: `src/chain/hash_chain.py:76-105`**

```python
def verify_chain(self) -> dict:
    for i, entry in enumerate(self.chain):
        # 1. 校验 prev_hash 连续性
        if entry["prev_hash"] != expected_prev:
            return {"is_valid": False, "broken_position": i}

        # 2. 重算 chain_hash
        raw = (entry["prev_hash"] + entry["merkle_root"]).encode()
        expected_hash = hashlib.sha256(raw).hexdigest()
        if entry["chain_hash"] != expected_hash:
            return {"is_valid": False, "broken_position": i}  # 发现篡改！

    return {"is_valid": True}
```

**链上合约层面同样有完整性验证**：

**文件: `bcos/contract/AuditLedger.sol`** (函数 `verifyChainIntegrity`)

```solidity
// Solidity 中的链完整性验证
for (uint256 i = 0; i < total; i++) {
    // (1) 校验 prevHash
    if (keccak256(bytes(record.prevHash)) != keccak256(bytes(expectedPrev))) {
        return (false, total, int256(i), ...);  // 链断裂
    }
    // (2) 重算 recordHash
    string memory expectedHash = _computeRecordHash(...);
    if (keccak256(bytes(record.recordHash)) != keccak256(bytes(expectedHash))) {
        return (false, total, int256(i), ...);  // 数据被篡改
    }
}
```

### 测试验证

**文件: `tests/test_integration.py`**

测试直接验证了篡改检测能力：

```python
def test_scenario_log_tamper_detection(self, ...):
    mock_es.tamper_log(tampered_log["log_id"], "command", "rm -rf /")
    # 重新计算 Merkle Root
    local_root = recalculated_tree.get_root()
    # 从链上取原始 Merkle Root
    original_root = chain_record.merkle_root
    # 比对——必定不一致
    assert local_root != original_root
```

---

## 5. 智能合约存证

### 原理

智能合约是运行在区块链上的程序，其状态由全网共识节点共同维护。一旦交易被共识确认，数据就永久记录在区块链上，任何单方面修改都无法生效。

### 代码实现

**文件: `bcos/contract/AuditLedger.sol`** — Solidity 合约

Solidity 合约的核心数据结构就是链式账本：

```solidity
// Solidity 中的存证记录
struct AuditRecord {
    string batchId;
    string merkleRoot;
    string prevHash;       // 哈希指针
    string recordHash;     // 本条哈希
    string signature;      // Ed25519 签名
    string signerKeyFp;    // 签名者公钥指纹
    string timestamp;      // 上链时间
    uint256 logCount;      // 日志条数
}

// 存储在链上状态中
AuditRecord[] private _records;       // 有序记录列表
mapping(bytes32 => bool) private _exists;  // 去重映射
```

**文件: `bcos/contract/audit_ledger.py`** — Python 等价实现

在 Debug 模式下，Python 版的 `AuditLedger` 类模拟了完全相同的逻辑（计算哈希、校验唯一性、持久化），使得开发调试无需真实链环境。

**文件: `src/ledger/contract.py`** — 合约调用封装

应用层通过 `AuditContract` 与合约交互，根据 `AUDIT_SYSTEM_MODE` 自动选择 MockBCOS 或真实 BCOS：

```python
# ledger/__init__.py
if IS_DEBUG:
    from src.debug.mock_bcos import MockBCOS as BCOSClient
else:
    from src.ledger.bcos_client import BCOSClient
```

---

## 6. PBFT 拜占庭容错

### 原理

PBFT（Practical Byzantine Fault Tolerance）是联盟链中最常用的共识算法。在 4 节点配置下（`3f+1 = 4`），可容忍 1 个节点作恶或故障。

```
Client   ──Request──► Primary
                        │
           ┌───── Pre-Prepare ─────┐
           │          │            │
      ┌─Prepare──┐  ┌─Prepare──┐  ┌─Prepare──┐
      │          │  │          │  │          │
      ◄─Commit──►  ◄─Commit──►  ◄─Commit──►
      │          │  │          │  │          │
      ◄──Reply───  ◄──Reply───  ◄──Reply───
```

### 代码体现

**文件: `bcos/conf/config.toml`**

```toml
[consensus]
type = "pbft"
node_count = 4
# 3f+1 = 4 → 可容忍 1 个拜占庭节点
block_tx_count_limit = 1000

[[consensus_node]]
node_id = "node1"
ip = "bcos-node1"

[[consensus_node]]
node_id = "node2"
ip = "bcos-node2"

# ...共 4 个节点
```

**文件: `docker-compose.yml`** — 定义了 4 个 BCOS 容器节点，组成 P2P 网络。

### 为什么是 4 个节点？

假设作恶节点数为 f，总节点数 N 需满足：
- `N ≥ 3f + 1`（PBFT 容错上限）
- `f = 1` → `N ≥ 4`

当 `f = 1` 时，即使有一个节点故意不响应或发送错误数据，剩下 3 个正常节点仍能通过两轮投票（Prepare + Commit）达成共识。

---

## 7. 去中心化验证

### 原理

在联盟链中，任何持有合约地址和公钥的参与者都可以独立验证数据的真实性，无需信任某个中央服务器。

### 代码实现

整个验证流程不依赖任何中心化权威：

```
用户提交 log_id
    ↓
从 ES 取日志原文（任何人都可以查）
    ↓
重建 Merkle 树，计算本地 Merkle Root（确定性算法，谁算都一样）
    ↓
从链上合约查该批次的存证记录（任何人都可以调合约查询）
    ↓
比对 Merkle Root + 验签
    ↓
输出：已验证 / 被篡改
```

**文件: `src/storage/query.py:38-139`** — 完整的去中心化验证流程：

```python
def verify_log(self, log_id, public_key_path=None):
    # 1. ES中取日志（链下存储，任何人都可访问）
    log_entry = self._es.get_log_by_id(log_id)
    # 2. 取回同批次所有日志
    batch_logs = self._es.get_logs_by_batch(batch_id)
    # 3. 重建 Merkle 树，计算本地 Root
    tree = MerkleTree(batch_logs)
    local_merkle_root = tree.get_root()
    # 4. 从链上查询存证记录（智能合约查询，无需 gas）
    chain_record = self._contract.query_by_batch_id(batch_id)
    # 5. 比对 + 验签
    merkle_match = (local_merkle_root == chain_record["merkle_root"])
    signature_valid = verify(data, sig_bytes, pub_key)
    # 6. 综合判断
    verified = merkle_match and signature_valid
```

CLI 工具集成了同样的验证能力，任何人都可以独立运行：

```bash
python -m src.cli.audit_cli verify --log-id <log_id> --public-key /path/to/pub.pem
python -m src.cli.audit_cli chain-verify
```

---

## 8. 完整数据流回顾

将以上所有原理串联起来，一次完整的"日志 → 存证 → 验证"流程如下：

### 上链流程

```
日志批次到达
    │
    ▼
① Merkle 树构建 ─────────────── 原理: 数据聚合
    │
    ▼
② 哈希链追加 ────────────────── 原理: 链式结构
    │
    ▼
③ Ed25519 签名 ──────────────── 原理: 数字签名
    │
    ▼
④ 智能合约 recordAudit() ───── 原理: 合约存证
    │
    ▼
⑤ PBFT 共识确认 ─────────────── 原理: 拜占庭容错
    │
    ▼
⑥ 写入区块 ─────────────────── 原理: 不可篡改
```

### 验证流程

```
审计员提供 log_id
    │
    ▼
① 从 ES 取日志原文
    │
    ▼
② 重建 Merkle 树 ───────────── 原理: 去中心化验证
    │
    ▼
③ 从链上合约取存证记录
    │
    ▼
④ 比对 Merkle Root + 验签
    │
    ▼
⑤ 输出验证结果
```

---

## 总结

| 区块链原理 | 代码位置 | 一句话实现 |
|-----------|---------|-----------|
| 链式哈希结构 | `src/chain/hash_chain.py` | `chain_hash = SHA256(prev_hash + merkle_root)` |
| Merkle 树聚合 | `src/merkle/tree.py` | 自底向上 SHA-256 逐层合并 |
| 数字签名 | `src/crypto/signer.py` | Ed25519 签名 chain_hash |
| 不可篡改性 | `hash_chain.verify_chain()` | 遍历重算哈希，不匹配即断裂 |
| 智能合约 | `bcos/contract/AuditLedger.sol` | Solidity 链式存证 + 完整性验证 |
| PBFT 共识 | `bcos/conf/config.toml` | 4 节点，容忍 1 个作恶 |
| 去中心化验证 | `src/storage/query.py` | Merkle Root 比对 + Ed25519 验签 |
