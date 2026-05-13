# API接口规范

Base URL: `/api/v1/audit`

## 1. 提交批次上链

```
POST /api/v1/audit/batch
```

### 请求体

```json
{
  "batch_id": "batch_20260508_1430",
  "logs": [
    {
      "log_id": "abc123",
      "operator": "zhangsan",
      "ip": "192.168.1.100",
      "command": "rm -rf /data/temp/*",
      "target": "/data/temp/",
      "result": "success",
      "timestamp": "2026-05-08T14:23:01Z"
    }
  ]
}
```

### 响应 (201 Created)

```json
{
  "batch_id": "batch_20260508_1430",
  "merkle_root": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "chain_hash": "a1b2c3d4e5f6...",
  "record_hash": "b2c3d4e5f6...",
  "log_count": 8327,
  "timestamp": "2026-05-08T14:30:00Z"
}
```

### 错误

| 状态码 | 含义 |
|--------|------|
| 400 | batch_id或logs缺失 |
| 409 | batch_id重复 |
| 500 | 服务器内部错误 |

## 2. 搜索操作日志

```
GET /api/v1/audit/search
```

### 查询参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| operator | string | 否 | 操作者精确匹配 |
| start_time | string | 否 | 起始时间 (ISO 8601) |
| end_time | string | 否 | 结束时间 (ISO 8601) |
| keyword | string | 否 | 命令关键词模糊匹配 |
| page | int | 否 | 页码（默认1） |
| size | int | 否 | 每页条数（默认50，最大100） |

### 响应 (200 OK)

```json
{
  "results": [
    {
      "log_id": "abc123",
      "batch_id": "batch_20260508_1430",
      "operator": "zhangsan",
      "ip": "192.168.1.100",
      "command": "rm -rf /data/temp/*",
      "target": "/data/temp/",
      "result": "success",
      "timestamp": "2026-05-08T14:23:01Z"
    }
  ],
  "total": 1,
  "page": 1,
  "size": 50
}
```

## 3. 验证单条日志

```
POST /api/v1/audit/verify
```

### 请求体

```json
{
  "log_id": "abc123",
  "public_key_path": "/path/to/public.pem"
}
```

### 响应 (200 OK)

```json
{
  "log_id": "abc123",
  "batch_id": "batch_20260508_1430",
  "verified": true,
  "merkle_root_match": true,
  "signature_valid": true,
  "local_merkle_root": "e3b0c44298fc1c14...",
  "chain_merkle_root": "e3b0c44298fc1c14...",
  "message": "验证通过"
}
```

### 验证失败响应

```json
{
  "log_id": "abc123",
  "verified": false,
  "error": "merkle_root_mismatch",
  "message": "Merkle Root不一致，日志已被篡改"
}
```

### 错误码

| error | 含义 |
|-------|------|
| log_not_found | 日志未找到 |
| batch_id_missing | 日志缺少批次ID |
| batch_not_found | 批次在链上不存在 |
| merkle_root_mismatch | Merkle Root不一致 |
| signature_invalid | 签名无效 |
| chain_broken | 链完整性断裂 |

## 4. 验证整链完整性

```
GET /api/v1/audit/chain/integrity
```

### 响应 (200 OK)

```json
{
  "is_valid": true,
  "total_records": 42,
  "broken_position": -1,
  "first_batch_id": "batch_20260508_0800",
  "last_batch_id": "batch_20260508_1135"
}
```

## 5. 获取链摘要信息

```
GET /api/v1/audit/chain/info
```

### 响应 (200 OK)

```json
{
  "total_records": 42,
  "genesis_batch_id": "batch_20260508_0800",
  "genesis_time": "2026-05-08T08:00:00Z",
  "latest_batch_id": "batch_20260508_1135",
  "latest_time": "2026-05-08T11:35:00Z",
  "latest_record_hash": "a1b2c3d4..."
}
```

## 6. 查询链上存证记录

```
GET /api/v1/audit/record/{batch_id}
```

### 响应 (200 OK)

```json
{
  "batch_id": "batch_20260508_1430",
  "merkle_root": "e3b0c44298fc1c14...",
  "prev_hash": "0000000000000000...",
  "record_hash": "a1b2c3d4...",
  "signature": "base64_encoded_signature...",
  "signer_key_fp": "SHA256:abc123...",
  "timestamp": "2026-05-08T14:25:00Z",
  "log_count": 8327,
  "tx_hash": "0x1234..."
}
```

### 错误

| 状态码 | 含义 |
|--------|------|
| 404 | 记录不存在 |
