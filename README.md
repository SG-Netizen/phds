# PHDS - 个人健康数据主权协议

> **P**ersonal **H**ealth **D**ata **S**overeignty Protocol  
> 让每个人真正拥有自己的健康数据

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-green.svg)](https://www.python.org/)

---

> ⚠️ **项目阶段声明**
>
> 当前版本为**技术原型（v0.2.0）**，由单人持续开发，**未经第三方安全审计**，请勿直接用于生产环境处理真实个人健康数据。适用场景：技术学习、密码学原型验证、健康隐私方案预研。路线图公开，欢迎开发者参与测试与方案讨论。

---

## 项目简介

PHDS 是一套**去中心化**的个人健康数据主权协议及其开源 SDK 实现。

在当前的医疗体系中，患者的健康数据存储在医院的 HIS（医院信息系统）中，患者对自己数据的访问、控制和授权能力极为有限。PHDS 通过密码学手段解决这一问题：

- **你加密，你掌控**：数据在患者本地加密后再上传，存储方无法查看明文
- **你授权，他查看**：医生需要患者用私钥签发的 JWT 才能解密数据
- **随时可撤销**：授权有时效，可随时撤销，所有操作记录在案
- **匿名隐私**：公钥哈希作为标识，不暴露真实身份

### 核心特性

| 特性 | 技术方案 |
|------|----------|
| 密钥管理 | 手机号+PIN 简化模式（PBKDF2 密钥派生）+ Ed25519 + SM2 国密兼容 |
| 数据加密 | AES-256-GCM 认证加密 |
| 密钥交换 | ECIES（Ed25519→X25519 ECDH） |
| 授权机制 | 临时会话密钥 + 限时 JWT（EdDSA） |
| 数据完整性 | SHA-256 哈希校验 |
| 匿名标识 | 公钥 SHA-256 哈希 |

---

## 快速开始

### 环境要求

- Python 3.10+
- Windows / macOS / Linux

### 安装

```bash
# 克隆项目
git clone https://github.com/SG-Netizen/phds.git
cd phds

# 安装依赖
pip install -r requirements.txt
```

### 运行 Demo

**简化流程演示（推荐）**：

```bash
python demo/demo_lite_flow.py
```

手机号 + 6 位 PIN 即可完成 9 步完整流程：密钥派生 → 病历加密 → 链上存证 → 授权请求 → 患者审批 → 医生解密 → 授权过期 → 撤销日志 → 链完整性验证。

**SM2 国密演示**：

```bash
python demo/demo_sm2.py
```

演示 SM2 密钥生成 → 加密 → 解密的完整链路。

**患者端**：

```bash
python demo/demo_patient.py
```

演示手机号+PIN 密钥派生、病历加密、授权审批。

**医生端**：

```bash
python demo/demo_doctor.py
```

演示授权请求、JWT 验证、病历解密。

### 简化模式（手机号 + PIN，无需助记词）

PHDS 默认使用**手机号 + 6 位 PIN** 管理密钥。通过 PBKDF2 确定性派生，私钥不落盘，换设备后输入相同凭据即可恢复，无需管理助记词或密钥文件。

```bash
python demo/demo_lite_flow.py
```

### 启动 API 服务

```bash
uvicorn phds.sdk.api.server:app --reload
```

### 运行测试

```bash
# 运行全部测试（40 项）
python -m pytest tests/ -v

# 运行核心模块测试（28 项）
python -m pytest tests/test_core.py -v

# 运行链存证测试（12 项）
python -m pytest tests/test_chain.py -v
```

---

## 核心概念

### 密钥管理

```
手机号 + PIN → PBKDF2(10万次) → Ed25519 密钥对
  ├── 公钥 → SHA-256 → 公钥哈希（匿名 patient_id）
  └── 私钥 → 签名 JWT、签名授权
```

### 病历加密

```
病历明文 → AES-256-GCM(随机Nonce, 会话密钥) → 密文
密文哈希 = SHA-256(密文)  ← 用于完整性校验
```

### 授权流程

```
医生请求授权
    ↓
患者审批 → 生成临时会话密钥
    ↓
患者签发 JWT（EdDSA 签名）
    ↓
医生凭 JWT 获取密文 + 会话密钥解密
    ↓
授权过期 / 撤销 → JWT 失效
```

---

## 项目结构

```
phds/
├── README.md                    # 项目说明
├── LICENSE                      # MIT 许可证
├── CONTRIBUTING.md              # 贡献指南
├── protocol.md                  # 协议规范文档
├── requirements.txt             # Python 依赖
│
├── sdk/                         # PHDS SDK
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── keys.py              # Ed25519 + SM2 + PBKDF2
│   │   ├── crypto.py            # AES-256-GCM + ECIES
│   │   ├── auth.py              # JWT 授权 + 撤销 + 日志
│   │   └── chain.py             # 链上存证（轻量 PoW）
│   ├── records/
│   │   ├── __init__.py
│   │   ├── bio_record.py        # BioRecord 数据结构
│   │   └── authorization.py     # AuthorizationEvent 数据结构
│   └── api/
│       ├── __init__.py
│       └── server.py            # FastAPI 接口服务（6 个接口）
│
├── demo/
│   ├── demo_lite_flow.py        # 简化 9 步流程演示（推荐）
│   ├── demo_flow.py             # 完整 9 步流程演示（高级）
│   ├── demo_sm2.py              # SM2 国密加密解密演示
│   ├── demo_patient.py          # 患者端独立演示
│   └── demo_doctor.py           # 医生端独立演示
│
├── docs/
│   ├── ARCHITECTURE.md          # 系统架构文档
│   ├── DEPLOY.md                # 部署指南
│   └── ROADMAP.md               # 详细路线图
│
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI（Python 3.10/11/12）
│
└── tests/
    ├── test_core.py             # 核心模块测试（28 项）
    └── test_chain.py            # 链上存证测试（12 项）
```

---

## 架构设计

```
┌─────────────────────────────────────────────────────────┐
│                      应用层                              │
│  患者端 App  │  医生端 App  │  医院 HIS  │  研究机构      │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                   PHDS SDK                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐   │
│  │  keys.py │  │crypto.py │  │      auth.py         │   │
│  │ Ed25519  │  │AES-256   │  │ JWT签发/验证/撤销     │   │
│  │ SM2 国密 │  │ECIES     │  │ 会话密钥/授权日志     │   │
│  │ PBKDF2   │  │文件加密  │  │                      │   │
│  └──────────┘  └──────────┘  └──────────────────────┘   │
│                                                         │
│  ┌──────────────────┐  ┌──────────────────────────┐     │
│  │  bio_record.py   │  │  authorization.py         │     │
│  │  BioRecord       │  │  AuthorizationEvent       │     │
│  └──────────────────┘  └──────────────────────────┘     │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│               存储层（加密数据）                          │
│   FastAPI Server  │  IPFS  │  云存储  │  本地文件        │
└─────────────────────────────────────────────────────────┘
```

---

## 与 BSP 的差异

| 维度 | BSP (Bluesky) | PHDS |
|------|---------------|------|
| **领域** | 通用社交数据 | 健康医疗数据 |
| **密钥算法** | P-256 (ECDSA) | Ed25519 + SM2 国密兼容 |
| **加密方案** | 未指定 | AES-256-GCM + ECIES |
| **授权粒度** | 仓库级 | 记录级 + JWT |
| **会话管理** | 无 | 临时会话密钥，到期失效 |
| **国密支持** | 无 | SM2 / SM4（规划中） |
| **合规导向** | 一般 | HIPAA / 个人信息保护法 |

---

## 路线图

详细规划见 [docs/ROADMAP.md](docs/ROADMAP.md)。

- [x] **v0.1.0** — 核心协议：Ed25519 密钥、AES-256-GCM 加密、JWT 授权、FastAPI 接口
- [x] **v0.1.1** — 链上存证 + SM2 国密演示 + 完整文档
- [x] **v0.2.0** — 简化模式上线：手机号+PIN 密钥派生、API 服务、完整测试
- [ ] **v0.3.0** — 安全性增强：SSS 密钥分片恢复、密钥轮换、FHIR 适配器、安全自评文档
- [ ] **v0.4.0** — 分布式存储：IPFS 集成、ZKP 零知识证明
- [ ] **v0.5.0** — 联邦学习：跨机构联合计算
- [ ] **v1.0.0** — 生产级稳定版：审计、合规、性能优化

---

## 贡献

欢迎提交 Issue 和 Pull Request。请确保代码通过 `python -m pytest tests/ -v`。

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件。
