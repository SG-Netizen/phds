"""
PHDS FastAPI 接口服务

实现协议规范中的 7 个 RESTful 接口（含新增 /token）：
  POST   /token                        - 签发 API 访问令牌
  POST   /bio-records                  - 上传加密病历
  GET    /bio-records/{patient_hash}   - 查询患者病历列表
  POST   /authorization/request        - 请求授权
  POST   /authorization/approve        - 批准授权
  POST   /authorization/revoke         - 撤销授权
  GET    /authorization/log            - 查看授权日志

所有接口（除 /token 外）受 JWT Bearer Token 认证中间件保护
所有接口受 IP 滑动窗口限流保护

启动方式::

    uvicorn sdk.api.server:app --reload
"""
from __future__ import annotations

import base64
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

from ..core.keys import (
    load_public_key,
    load_private_key,
    public_key_hash,
    export_public_key,
    export_private_key,
)
from ..core.crypto import (
    encrypt_for_recipient,
    decrypt_from_sender,
    aes_encrypt,
    aes_decrypt,
)
from ..core.auth import (
    create_authorization_jwt,
    verify_authorization_jwt,
    generate_session_key,
    AuthorizationLogEntry,
)
from ..records.bio_record import BioRecord, RecordMetadata
from ..records.authorization import AuthorizationEvent, AuthorizationStatus

# ── 新增模块 ───────────────────────────────────────────────
from .auth_middleware import (
    get_current_user,
    verify_api_token,
    create_api_token,
    get_server_key_pair,
    get_server_public_pem,
)
from .rate_limit import get_rate_limiter, rate_limit_middleware


# ============================================================
# 配置（使用 pydantic-settings 管理，支持环境变量覆盖）
# ============================================================

class Settings(BaseSettings):
    """PHDS 服务配置。

    所有配置项均支持环境变量覆盖，优先级：环境变量 > .env 文件 > 默认值。

    Attributes:
        data_dir:            数据目录
        db_path:             SQLite 数据库文件路径
        jwt_key_path:        服务端 JWT 密钥存储路径（预留）
        rate_limit_max:      每分钟最大请求数
        rate_limit_window:   限流窗口秒数
        server_host:         服务监听地址
        server_port:         服务监听端口
    """

    model_config = {"env_prefix": "PHDS_", "env_file": ".env", "extra": "ignore"}

    data_dir: str = str(Path(__file__).resolve().parents[3] / "data")
    db_path: str = ""
    jwt_key_path: str = ""
    rate_limit_max: int = 60
    rate_limit_window: int = 60
    server_host: str = "0.0.0.0"
    server_port: int = 8000

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # 自动推导子路径
        if not self.db_path:
            self.db_path = os.path.join(self.data_dir, "phds.db")
        if not self.jwt_key_path:
            self.jwt_key_path = os.path.join(self.data_dir, "server_key.pem")


_settings = Settings()

# ── 确保数据目录存在 ─────────────────────────────────────
os.makedirs(_settings.data_dir, exist_ok=True)


# ============================================================
# 持久化存储（SQLite）
# ============================================================

from ..storage.database import DatabaseManager
from ..storage.revocation_store import RevocationStore

_db: Optional[DatabaseManager] = None
_revocation_store: Optional[RevocationStore] = None


def get_db() -> DatabaseManager:
    """获取数据库实例（延迟初始化）。"""
    global _db
    if _db is None:
        _db = DatabaseManager(db_path=_settings.db_path)
        _db.init_db()
    return _db


def get_revocation_store() -> RevocationStore:
    """获取撤销存储实例（延迟初始化，与 DatabaseManager 共享 Engine）。"""
    global _revocation_store
    if _revocation_store is None:
        db = get_db()
        _revocation_store = RevocationStore(db.engine)
        _revocation_store.create_tables()
    return _revocation_store


# ============================================================
# 应用生命周期
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用启动/关闭时的生命周期管理。

    启动时：初始化数据库和撤销存储、建表、生成服务端密钥
    关闭时：清理资源
    """
    # 启动阶段
    db = get_db()
    db.init_db()
    rev = get_revocation_store()
    rev.create_tables()
    # 预生成服务端密钥对
    pub, priv = get_server_key_pair()
    pub_pem = export_public_key(pub)
    print(f"[PHDS] 服务启动完成")
    print(f"[PHDS] 数据目录: {_settings.data_dir}")
    print(f"[PHDS] 数据库:   {_settings.db_path}")
    print(f"[PHDS] 服务端公钥哈希: {public_key_hash(pub)[:16]}...")
    yield
    # 关闭阶段
    print("[PHDS] 服务关闭")


# ============================================================
# FastAPI 应用
# ============================================================

app = FastAPI(
    title="PHDS Protocol API",
    description="个人健康数据主权协议 - API 服务",
    version="0.2.0",
    lifespan=lifespan,
)

# ── 全局中间件：限流 ─────────────────────────────────────
app.middleware("http")(rate_limit_middleware)


# ============================================================
# Pydantic 请求/响应模型
# ============================================================

class TokenRequest(BaseModel):
    """签发 API 令牌请求。"""
    subject: str = Field(..., description="令牌持有者标识（应用 ID 或用户标识）")
    scope: str = Field(default="api_access", description="权限范围")
    expire_seconds: int = Field(default=3600, description="有效期（秒）")


class TokenResponse(BaseModel):
    """签发 API 令牌响应。"""
    access_token: str = Field(..., description="JWT 访问令牌")
    token_type: str = Field(default="bearer", description="令牌类型")
    expires_in: int = Field(..., description="有效期（秒）")
    server_public_key_pem: str = Field(..., description="服务端公钥 PEM")


class BioRecordUploadRequest(BaseModel):
    """上传病历请求。"""
    patient_pubkey_pem: str = Field(..., description="患者 Ed25519 公钥（PEM）")
    encrypted_data_b64: str = Field(..., description="加密后的数据（base64）")
    encrypted_data_url: str = Field(default="", description="加密数据存储 URL")
    hospital_id: str = Field(default="", description="医院 ID")
    record_type: str = Field(default="", description="记录类型")
    description: str = Field(default="", description="描述")


class BioRecordResponse(BaseModel):
    """病历响应。"""
    record_id: str
    patient_pubkey_hash: str
    encrypted_data_url: str
    data_hash: str
    metadata: dict


class AuthorizationRequestReq(BaseModel):
    """授权请求。"""
    requester_id: str = Field(..., description="请求方标识")
    requester_pubkey_pem: str = Field(..., description="请求方公钥（PEM）")
    patient_pubkey_pem: str = Field(..., description="患者公钥（PEM）")
    scope: str = Field(default="read", description="权限范围")


class AuthorizationApproveReq(BaseModel):
    """批准授权请求。"""
    request_id: str = Field(..., description="请求 ID")
    patient_privkey_pem: str = Field(..., description="患者私钥（PEM）—用于签名 JWT")
    expire_seconds: int = Field(default=3600, description="有效期（秒）")


class AuthorizationRevokeReq(BaseModel):
    """撤销授权请求。"""
    jti: str = Field(..., description="JWT ID")
    patient_privkey_pem: str = Field(..., description="患者私钥（PEM）")
    patient_pubkey_pem: str = Field(..., description="患者公钥（PEM）")


# ============================================================
# /token — 签发 API 访问令牌（无需认证）
# ============================================================

@app.post("/token", response_model=TokenResponse)
def issue_token(req: TokenRequest):
    """签发 API 访问令牌。

    使用服务端密钥对签发 JWT，客户端凭此令牌访问其他受保护接口。

    此接口本身无需认证。
    """
    token = create_api_token(
        subject=req.subject,
        scope=req.scope,
        expire_seconds=req.expire_seconds,
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=req.expire_seconds,
        server_public_key_pem=get_server_public_pem(),
    )


# ============================================================
# 病历接口（受认证保护）
# ============================================================

@app.post("/bio-records", response_model=BioRecordResponse)
def upload_bio_record(
    req: BioRecordUploadRequest,
    subject: str = Depends(get_current_user),
    _limiter=Depends(get_rate_limiter),
):
    """上传加密病历。

    接收加密后的数据和元数据，创建 BioRecord 并持久化到 SQLite。
    """
    pubkey = load_public_key(req.patient_pubkey_pem)
    patient_hash = public_key_hash(pubkey)

    encrypted_data = base64.b64decode(req.encrypted_data_b64)

    metadata = RecordMetadata(
        hospital_id=req.hospital_id,
        record_type=req.record_type,
        description=req.description,
    )

    record = BioRecord.create(
        patient_pubkey_hash=patient_hash,
        encrypted_data_url=req.encrypted_data_url
        or f"phds://{patient_hash}/records/{uuid.uuid4().hex[:8]}",
        encrypted_data=encrypted_data,
        metadata=metadata,
    )

    # 持久化到 SQLite
    db = get_db()
    db.add_bio_record({
        "record_id": record.record_id,
        "patient_pubkey_hash": record.patient_pubkey_hash,
        "encrypted_data_url": record.encrypted_data_url,
        "data_hash": record.data_hash,
        "hospital_id": metadata.hospital_id,
        "record_type": metadata.record_type,
        "description": metadata.description,
        "metadata": metadata.to_dict(),
        "created_at": metadata.created_at,
    })

    return BioRecordResponse(**record.to_dict())


@app.get("/bio-records/{patient_hash}", response_model=List[BioRecordResponse])
def list_bio_records(
    patient_hash: str,
    subject: str = Depends(get_current_user),
    _limiter=Depends(get_rate_limiter),
):
    """查询患者病历列表。

    Args:
        patient_hash: 患者公钥哈希
    """
    db = get_db()
    rows = db.get_bio_records_by_patient(patient_hash)
    return [
        BioRecordResponse(
            record_id=r.record_id,
            patient_pubkey_hash=r.patient_pubkey_hash,
            encrypted_data_url=r.encrypted_data_url,
            data_hash=r.data_hash,
            metadata=r.to_dict().get("metadata", {}),
        )
        for r in rows
    ]


# ============================================================
# 授权接口（受认证保护）
# ============================================================

@app.post("/authorization/request")
def request_authorization(
    req: AuthorizationRequestReq,
    subject: str = Depends(get_current_user),
    _limiter=Depends(get_rate_limiter),
):
    """发起授权请求。"""
    patient_pubkey = load_public_key(req.patient_pubkey_pem)
    patient_hash = public_key_hash(patient_pubkey)

    event = AuthorizationEvent(
        patient_pubkey_hash=patient_hash,
        requester_id=req.requester_id,
        scope=req.scope,
    )

    # 持久化到 SQLite
    db = get_db()
    db.add_authorization(event.to_dict())

    # 记录审计日志
    from ..core.auth import AuthorizationLogEntry
    log_entry = AuthorizationLogEntry(
        action="request",
        requester_id=req.requester_id,
        patient_hash=patient_hash,
        scope=req.scope,
    )
    db.add_auth_log(log_entry.to_dict())

    return event.to_dict()


@app.post("/authorization/approve")
def approve_authorization(
    req: AuthorizationApproveReq,
    subject: str = Depends(get_current_user),
    _limiter=Depends(get_rate_limiter),
):
    """批准授权。"""
    db = get_db()
    row = db.get_authorization(req.request_id)
    if row is None:
        raise HTTPException(status_code=404, detail="授权请求不存在")
    if row.status != AuthorizationStatus.PENDING:
        raise HTTPException(status_code=400, detail="该请求已处理过")

    patient_privkey = load_private_key(req.patient_privkey_pem)
    patient_pubkey = patient_privkey.public_key()

    session_key = generate_session_key()
    session_key_b64 = base64.b64encode(session_key).decode()

    jwt_token = create_authorization_jwt(
        patient_private_key=patient_privkey,
        patient_public_key=patient_pubkey,
        requester_id=row.requester_id,
        scope=row.scope,
        expire_seconds=req.expire_seconds,
    )

    payload = verify_authorization_jwt(jwt_token, patient_pubkey)
    if payload is None:
        raise HTTPException(status_code=500, detail="JWT 签发后验证失败")
    jti = payload["jti"]
    expire_at = payload["exp"]

    # 更新 SQLite
    db.update_authorization(req.request_id, {
        "session_key": session_key_b64,
        "expire_at": float(expire_at),
        "status": AuthorizationStatus.APPROVED,
        "jti": jti,
    })

    # 记录审计日志
    log_entry = AuthorizationLogEntry(
        action="approve",
        requester_id=row.requester_id,
        patient_hash=row.patient_pubkey_hash,
        jti=jti,
        scope=row.scope,
        expire_at=float(expire_at),
    )
    db.add_auth_log(log_entry.to_dict())

    return {
        "request_id": req.request_id,
        "status": AuthorizationStatus.APPROVED,
        "authorization_token": jwt_token,
        "jti": jti,
    }


@app.post("/authorization/revoke")
def revoke_authorization_endpoint(
    req: AuthorizationRevokeReq,
    subject: str = Depends(get_current_user),
    _limiter=Depends(get_rate_limiter),
):
    """撤销授权。

    将 JWT ID 加入 SQLite 撤销存储。
    """
    patient_pubkey = load_public_key(req.patient_pubkey_pem)

    db = get_db()
    row = db.get_authorization_by_jti(req.jti)
    if row is None:
        raise HTTPException(status_code=404, detail="未找到对应的授权事件")
    if row.status != AuthorizationStatus.APPROVED:
        raise HTTPException(status_code=400, detail="该授权不处于已批准状态")

    # 加入撤销存储
    rev = get_revocation_store()
    rev.revoke(req.jti, reason="用户主动撤销")

    # 更新 SQLite 状态
    db.update_authorization(row.request_id, {"status": AuthorizationStatus.REVOKED})

    # 记录审计日志
    log_entry = AuthorizationLogEntry(
        action="revoke",
        requester_id=row.requester_id,
        patient_hash=row.patient_pubkey_hash,
        jti=req.jti,
        scope=row.scope,
    )
    db.add_auth_log(log_entry.to_dict())

    return {"status": "revoked", "jti": req.jti}


@app.get("/authorization/log")
def get_authorization_log(
    subject: str = Depends(get_current_user),
    _limiter=Depends(get_rate_limiter),
):
    """查看全部授权日志。"""
    db = get_db()
    entries = db.list_auth_logs(limit=200)
    return [e.to_dict() for e in entries]
