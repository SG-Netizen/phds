# PHDS 协议规范 v0.1.0

## 1. 协议概述

### 1.1 名称与版本

- **协议名称**: Personal Health Data Sovereignty（个人健康数据主权协议）
- **简称**: PHDS
- **版本**: 0.1.0

### 1.2 设计目标

PHDS 是一套去中心化的个人健康数据主权协议，核心目标：

1. **数据主权归个人**：患者拥有自己健康数据的完整控制权，不依赖第三方平台
2. **最小权限授权**：采用临时会话密钥 + 限时 JWT，每次访问都需明确授权
3. **端到端加密**：数据在患者端加密，传输和存储全程保持加密状态
4. **隐私匿名化**：患者通过公钥哈希标识，无需暴露真实身份
5. **可审计可撤销**：所有授权事件记录在日志中，支持随时撤销

### 1.3 与 BSP（Bluesky Storage Protocol）的差异

| 维度 | BSP | PHDS |
|------|-----|------|
| 领域 | 通用社交数据 | 健康医疗数据 |
| 密钥算法 | P-256（ECDSA） | Ed25519 + SM2 国密兼容 |
| 加密方案 | 未指定 | AES-256-GCM + ECIES |
| 授权机制 | 仓库级授权 | 记录级授权 + JWT |
| 合规要求 | 一般 | HIPAA / 个人信息保护法导向 |
| 会话管理 | 无 | 临时会话密钥，到期自动失效 |

---

## 2. 核心概念

### 2.1 参与者

| 角色 | 说明 |
|------|------|
| **患者（Patient）** | 健康数据的所有者，持有 Ed25519 密钥对 |
| **请求方（Requester）** | 希望访问患者数据的实体（医生、医院、研究机构） |
| **存储节点（Storage Node）** | 存储加密数据的服务器，无法解密 |

### 2.2 密钥体系

```
患者密钥对 ─── Ed25519 ─┬── 公钥 → SHA-256 → 公钥哈希（匿名标识）
                        └── 私钥 → 签名 JWT、解密会话密钥

临时会话密钥 ── AES-256 ─── 每次授权生成，用于加密病历
```

### 2.3 数据模型

#### BioRecord（生物医学记录）

```json
{
  "record_id": "uuid",
  "patient_pubkey_hash": "sha256-hex",
  "encrypted_data_url": "phds://...",
  "data_hash": "sha256-of-encrypted-data",
  "metadata": {
    "hospital_id": "string",
    "record_type": "lab_report | prescription | imaging | ...",
    "description": "string",
    "created_at": 1234567890.0,
    "extra": {}
  }
}
```

#### AuthorizationEvent（授权事件）

```json
{
  "request_id": "uuid",
  "patient_pubkey_hash": "sha256-hex",
  "requester_id": "sha256-hex",
  "session_key": "base64-aes-key",
  "expire_at": 1234567890.0,
  "status": "pending | approved | revoked | expired | denied",
  "scope": "read | write",
  "jti": "jwt-id"
}
```

---

## 3. 加密方案

### 3.1 病历数据加密（AES-256-GCM）

```
明文 → AES-256-GCM(随机Nonce, 会话密钥) → 密文
密文格式: nonce(12字节) || ciphertext || tag(16字节)
```

### 3.2 密钥交换（ECIES 风格）

```
发送方 Ed25519 私钥 → X25519 私钥
接收方 Ed25519 公钥 → X25519 公钥

共享密钥 = ECDH(X25519私钥, X25519公钥)
AES密钥 = HKDF-SHA256(共享密钥, salt=None, info="phds-ecies-v1")
密文 = AES-256-GCM(AES密钥, 明文)
```

### 3.3 会话密钥传递

```
患者生成随机 AES-256 会话密钥
    ↓
用请求方公钥 ECIES 加密会话密钥
    ↓
通过安全通道传递给请求方
```

---

## 4. 授权流程

### 4.1 完整交互流程

```
患者(Alice)              存储节点             医生(Bob)
    │                       │                    │
    │── 1. 加密病历 ────────→│                    │
    │   (AES-256-GCM)       │                    │
    │                       │                    │
    │                       │←── 2. 请求授权 ────│
    │                       │   (request_id)     │
    │                       │                    │
    │←── 3. 审批请求 ───────│                    │
    │                       │                    │
    │── 4. 签发JWT+会话密钥 →│                    │
    │   (EdDSA签名)         │                    │
    │                       │── 5. 转发凭证 ────→│
    │                       │   (JWT+session)    │
    │                       │                    │
    │                       │←── 6. 请求数据 ────│
    │                       │   (出示JWT)        │
    │                       │── 7. 验证JWT ─────→│
    │                       │── 8. 返回密文 ────→│
    │                       │                    │
    │                       │       9. 会话密钥解密病历
    │                       │                    │
    │── 10. 撤销授权 ──────→│                    │
    │   (jti→撤销列表)      │                    │
```

### 4.2 JWT 载荷规范

```json
{
  "sub": "患者公钥哈希",
  "requester": "请求方公钥哈希",
  "scope": "read",
  "exp": 1234567890,
  "jti": "唯一 JWT ID",
  "iat": 1234567890,
  "iss": "phds-protocol-v1"
}
```

- **签名算法**: EdDSA（Ed25519）
- **默认有效期**: 3600 秒（1 小时）

---

## 5. API 接口

### 5.1 病历管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/bio-records` | 上传加密病历 |
| GET | `/bio-records/{patient_hash}` | 查询患者病历列表 |

#### POST /bio-records

请求体：

```json
{
  "patient_pubkey_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "encrypted_data_b64": "base64-encoded-ciphertext",
  "encrypted_data_url": "phds://...",
  "hospital_id": "hospital_001",
  "record_type": "lab_report",
  "description": "化验报告"
}
```

响应：BioRecord JSON

#### GET /bio-records/{patient_hash}

返回该患者所有 BioRecord 列表。

### 5.2 授权管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/authorization/request` | 发起授权请求 |
| POST | `/authorization/approve` | 批准授权 |
| POST | `/authorization/revoke` | 撤销授权 |
| GET | `/authorization/log` | 查看授权日志 |

#### POST /authorization/request

```json
{
  "requester_id": "doctor_hash",
  "requester_pubkey_pem": "...",
  "patient_pubkey_pem": "...",
  "scope": "read"
}
```

#### POST /authorization/approve

```json
{
  "request_id": "...",
  "patient_privkey_pem": "...",
  "expire_seconds": 3600
}
```

#### POST /authorization/revoke

```json
{
  "jti": "...",
  "patient_privkey_pem": "...",
  "patient_pubkey_pem": "..."
}
```

---

## 6. 安全考量

### 6.1 密钥安全

- 私钥**永不离开**患者设备
- 私钥通过手机号+PIN 本地派生，换设备可恢复，无需备份助记词
- 会话密钥一次性使用，过期即失效

### 6.2 数据安全

- AES-256-GCM 提供认证加密（防篡改）
- BioRecord.data_hash 提供完整性校验
- 存储节点只保存密文，无法解密

### 6.3 隐私保护

- 患者标识为公钥哈希，不关联真实身份
- 授权最小化：默认只读、限时、可撤销
- 授权日志记录但不泄露病历内容

### 6.4 国密合规

- 支持 SM2 密钥对（通过 gmssl 库）
- 可与 Ed25519 并存，满足国内合规场景

---

## 7. 路线图

- [x] v0.1.0: 核心协议、Ed25519 密钥、AES-256-GCM 加密、JWT 授权
- [ ] v0.2.0: 国密 SM2/SM4 完整支持、SM9 标识密码
- [ ] v0.3.0: 分布式存储节点、IPFS 集成
- [ ] v0.4.0: 零知识证明（ZKP）验证
- [ ] v0.5.0: 跨机构联合计算（联邦学习）
- [ ] v1.0.0: 生产级稳定版
