"""
PHDS 授权事件数据结构（AuthorizationEvent）

记录患者与请求方之间的授权生命周期：
  request → approve → expire / revoke
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional


# 授权状态枚举
class AuthorizationStatus:
    PENDING = "pending"      # 等待审批
    APPROVED = "approved"    # 已批准
    REVOKED = "revoked"      # 已撤销
    EXPIRED = "expired"      # 已过期
    DENIED = "denied"        # 已拒绝


@dataclass
class AuthorizationEvent:
    """授权事件。

    Attributes:
        request_id:           请求唯一 ID
        patient_pubkey_hash:  患者公钥哈希
        requester_id:         请求方标识
        session_key:          会话密钥（base64 编码，仅在 approved 时有效）
        expire_at:            过期时间（Unix 时间戳）
        status:               状态
        scope:                权限范围
        created_at:           创建时间
        updated_at:           更新时间
        jti:                  JWT ID（approved 后关联）
    """
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    patient_pubkey_hash: str = ""
    requester_id: str = ""
    session_key: str = ""
    expire_at: float = 0.0
    status: str = AuthorizationStatus.PENDING
    scope: str = "read"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    jti: str = ""

    def is_active(self) -> bool:
        """检查授权当前是否有效。"""
        if self.status != AuthorizationStatus.APPROVED:
            return False
        return time.time() < self.expire_at

    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "patient_pubkey_hash": self.patient_pubkey_hash,
            "requester_id": self.requester_id,
            "session_key": self.session_key,
            "expire_at": self.expire_at,
            "status": self.status,
            "scope": self.scope,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "jti": self.jti,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "AuthorizationEvent":
        return cls(
            request_id=d.get("request_id", uuid.uuid4().hex),
            patient_pubkey_hash=d.get("patient_pubkey_hash", ""),
            requester_id=d.get("requester_id", ""),
            session_key=d.get("session_key", ""),
            expire_at=d.get("expire_at", 0.0),
            status=d.get("status", AuthorizationStatus.PENDING),
            scope=d.get("scope", "read"),
            created_at=d.get("created_at", time.time()),
            updated_at=d.get("updated_at", time.time()),
            jti=d.get("jti", ""),
        )

    def approve(self, session_key: str, expire_at: float, jti: str) -> None:
        """批准授权。

        Args:
            session_key: 会话密钥（base64 编码）
            expire_at:   过期时间戳
            jti:         JWT ID
        """
        self.status = AuthorizationStatus.APPROVED
        self.session_key = session_key
        self.expire_at = expire_at
        self.jti = jti
        self.updated_at = time.time()

    def revoke(self) -> None:
        """撤销授权。"""
        self.status = AuthorizationStatus.REVOKED
        self.updated_at = time.time()

    def deny(self) -> None:
        """拒绝授权。"""
        self.status = AuthorizationStatus.DENIED
        self.updated_at = time.time()
