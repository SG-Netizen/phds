# PHDS 系统架构文档

## 系统架构总览

PHDS 采用分层架构设计，从底层的密码学原语到上层的应用接口，逐层抽象：

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用层 (Application)                      │
│  患者端 App (密钥管理/加密授权)    医生端 App (请求/解密查看)     │
│  医院 HIS 系统集成              研究机构数据分析                  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ REST API / SDK
┌─────────────────────────────────▼───────────────────────────────┐
│                     API 网关层 (api/server.py)                    │
│  POST /bio-records         POST /authorization/request           │
│  GET  /bio-records/{hash}  POST /authorization/approve           │
│                            POST /authorization/revoke            │
│                            GET  /authorization/log               │
└──────┬──────────┬──────────┬──────────┬──────────────────────────┘
       │          │          │          │
┌──────▼──┐ ┌─────▼───┐ ┌───▼────┐ ┌──▼──────────┐
│ records │ │   auth  │ │ crypto │ │   chain     │
│ 模块    │ │  模块   │ │  模块  │ │   模块      │
└──────┬──┘ └────┬────┘ └───┬────┘ └──┬──────────┘
       │         │          │          │
┌──────▼─────────▼──────────▼──────────▼──────────────────────────┐
│                      密钥管理层 (keys.py)                         │
│  手机号+PIN 简化模式 / Ed25519 密钥对 / SM2 国密 / PEM 导入导出  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 核心模块说明

### 1. keys.py — 密钥管理

**职责**：身份密钥的生成、导入导出、助记词恢复。

| 功能 | 算法 | 说明 |
|------|------|------|
| 密钥对生成 | Ed25519 | 默认签名算法，用于 JWT 签发 |
| 国密密钥 | SM2 | gmssl 实现，用于国密合规场景 |
| 公钥哈希 | SHA-256 | 用作患者匿名标识 (patient_hash) |
| 密钥派生 | PBKDF2 (10万次) | 手机号 + PIN → Ed25519 密钥对（简化模式） |
| 密钥格式 | PEM (PKCS8) | 标准格式，可跨平台导入导出 |

**数据流**：

```
用户标识 + PIN → PBKDF2(100,000 iterations) → 32 字节种子 → Ed25519 密钥对
                                                    ├── public_key() → PEM → SHA-256 → patient_hash
                                                    └── private_bytes(PKCS8) → PEM

高级用户可选 BIP39 助记词模式（随机熵生成 24 词 → PBKDF2 → 密钥对）。
```

### 2. crypto.py — 数据加密

**职责**：数据加解密、密钥交换。

| 功能 | 算法 | 说明 |
|------|------|------|
| 对称加密 | AES-256-GCM | 认证加密，防篡改 |
| 密钥交换 | ECIES (Ed25519→X25519) | 双有理映射 + ECDH |
| 文件加密 | AES-256-GCM + 流式 | 支持大文件分块加密 |

**加密流程**：

```
病历明文
    │
    ▼
AES-256-GCM(random_nonce, session_key)
    │
    ├── ciphertext (nonce + tag + data)
    └── SHA-256(ciphertext) → data_hash (存证用)
```

**ECIES 混合加密**：

```
发送方临时密钥 → ECDH(临时私钥, 接收方公钥) → 共享密钥
共享密钥 → HKDF → AES 密钥
AES 密钥 → 加密数据
密文 = 临时公钥 + AES(共享密钥加密的数据)
```

### 3. auth.py — 授权管理

**职责**：访问控制、授权生命周期管理。

| 功能 | 实现 | 说明 |
|------|------|------|
| 授权签发 | JWT (EdDSA 签名) | 包含 requester、scope、过期时间 |
| 会话密钥 | 随机 32 字节 | 一次性 AES 密钥，加密具体数据 |
| 授权验证 | JWT 验签 + 过期检查 + 撤销列表 | 三重校验 |
| 授权撤销 | 撤销集合 (revocation set) | 按 jti 撤销 |
| 审计日志 | JSONL 格式本地文件 | 所有授权事件记录 |

**授权生命周期**：

```
请求 (PENDING) ──→ 批准 (APPROVED) ──→ 过期/撤销 (REVOKED)
  │                    │
  └──→ 拒绝 (DENIED)   └──→ 使用中 (ACTIVE, 有效期内的 APPROVED)
```

### 4. chain.py — 链上存证

**职责**：不可篡改的数据哈希存证。

| 功能 | 实现 | 说明 |
|------|------|------|
| 区块结构 | index + timestamp + data_hash + prev_hash + nonce | 标准区块链结构 |
| 共识 | 轻量 PoW | 前导零难度可调（默认 3） |
| 完整性验证 | 链式哈希校验 | 检测任何篡改 |
| 查询 | find_by_hash / find_by_data_hash | 按存证值检索 |

**防篡改原理**：

```
Block[N].prev_hash = Block[N-1].hash
Block[N].hash = SHA-256(index + timestamp + data_hash + prev_hash + nonce)

修改任何 Block 的 data_hash 或 prev_hash → 该 Block 的 hash 变化
→ 下一个 Block 的 prev_hash 不匹配 → 链断裂 → verify() 返回 False
```

### 5. records 模块

**bio_record.py**：BioRecord 数据结构，表示一份加密病历。

```
BioRecord {
    record_id: UUID            # 记录唯一标识
    patient_pubkey_hash: str   # 患者匿名 ID
    encrypted_data_url: str    # 密文存储位置
    data_hash: str             # SHA-256(密文)，用于完整性验证 + 链存证
    metadata: RecordMetadata   # 医院 / 类型 / 时间戳
}
```

**authorization.py**：AuthorizationEvent 数据结构，跟踪授权状态。

```
AuthorizationEvent {
    request_id: UUID           # 请求 ID
    patient_pubkey_hash: str   # 被授权患者
    requester_id: str          # 请求方标识
    session_key: str           # 会话密钥（批准后生成）
    expire_at: float           # 过期时间
    status: AuthorizationStatus # PENDING / APPROVED / DENIED / REVOKED
}
```

### 6. api/server.py — FastAPI 接口

提供 6 个 REST 接口，对应协议规范中的操作：

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/bio-records` | 上传加密病历 |
| GET | `/bio-records/{patient_hash}` | 查询患者病历列表 |
| POST | `/authorization/request` | 发起授权请求 |
| POST | `/authorization/approve` | 批准授权请求 |
| POST | `/authorization/revoke` | 撤销授权 |
| GET | `/authorization/log` | 查询授权日志 |

---

## 安全设计说明

### 威胁模型

| 威胁 | 防护措施 |
|------|----------|
| 存储方窃取数据 | 数据在患者端 AES-256-GCM 加密，存储方只有密文 |
| 中间人攻击 | ECIES 密钥交换 + JWT 签名验证 |
| 重放攻击 | JWT 含过期时间 + 一次性 nonce |
| 未授权访问 | JWT 三重校验（签名/过期/撤销列表） |
| 数据篡改 | SHA-256 完整性校验 + 链上存证 |
| 密钥泄露 | BIP39 助记词可恢复；私钥不在网络中传输 |

### 密钥管理安全

- 私钥仅在患者本地生成和存储
- 公钥哈希作为匿名标识，不泄露公钥原文
- 会话密钥一次性使用，用完即弃
- 所有密钥材料均为随机生成（os.urandom / secrets）

---

## 接口规范

### BioRecord 上传

```
POST /bio-records
Content-Type: application/json

{
    "patient_pubkey_hash": "a1b2c3...",
    "encrypted_data_url": "phds://a1b2c3/records/abc",
    "encrypted_data": "base64_encoded_ciphertext",
    "data_hash": "sha256_hash",
    "metadata": {
        "hospital_id": "hospital_001",
        "record_type": "lab_report",
        "timestamp": 1753161600
    }
}
```

### 授权请求

```
POST /authorization/request

{
    "patient_pubkey_hash": "a1b2c3...",
    "requester_id": "d4e5f6...",
    "scope": "read"
}
```

---

## 部署说明

### 开发环境

```bash
git clone <repo-url> phds
cd phds
pip install -r requirements.txt
uvicorn sdk.api.server:app --reload  # 监听 sdk/api/server.py 导入路径
```

### 生产环境

```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker sdk.api.server:app
```

推荐搭配 Nginx 反向代理，启用 HTTPS。
