"""
PHDS 授权管理模块

实现临时会话密钥 + JWT 的授权体系：

  - 生成临时会话密钥：每次授权创建一个一次性 AES 密钥
  - JWT 签发：包含过期时间、请求者公钥哈希、权限范围
  - JWT 验证：校验签名和过期时间
  - 撤销授权：将 JWT ID 加入本地撤销列表
  - 授权日志：记录完整的授权事件
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import jwt

from .keys import Ed25519PrivateKey, Ed25519PublicKey, public_key_hash
from .crypto import generate_aes_key


# JWT 签发者标识
ISSUER = "phds-protocol-v1"

# 默认授权有效期（秒）：1 小时
DEFAULT_EXPIRE_SECONDS = 3600

# 本地撤销列表存储路径（默认在用户目录下）
DEFAULT_REVOCATION_FILE = os.path.join(
    os.path.expanduser("~"), ".phds", "revocation.json"
)


# ============================================================
# 临时会话密钥
# ============================================================

def generate_session_key() -> bytes:
    """生成临时会话密钥（AES-256）。

    Returns:
        32 字节会话密钥
    """
    return generate_aes_key()


# ============================================================
# 授权 JWT
# ============================================================

def create_authorization_jwt(
    patient_private_key: Ed25519PrivateKey,
    patient_public_key: Ed25519PublicKey,
    requester_id: str,
    scope: str = "read",
    expire_seconds: int = DEFAULT_EXPIRE_SECONDS,
) -> str:
    """创建 PHDS 授权 JWT。

    载荷字段:
      - sub:患者公钥哈希（匿名标识）
      - requester:请求方标识
      - scope:权限范围（默认 read）
      - exp:过期时间
      - jti:JWT 唯一 ID（用于撤销）
      - iat:签发时间
      - iss:签发者

    Args:
        patient_private_key: 患者 Ed25519 私钥（用于签名）
        patient_public_key:  患者 Ed25519 公钥
        requester_id:        请求方标识（如医生公钥哈希）
        scope:               权限范围，默认 "read"
        expire_seconds:      有效期（秒），默认 3600

    Returns:
        JWT 字符串
    """
    now = int(time.time())
    payload = {
        "sub": public_key_hash(patient_public_key),
        "requester": requester_id,
        "scope": scope,
        "exp": now + expire_seconds,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "iss": ISSUER,
    }

    # 导出私钥 PEM 用于 JWT 签名
    from .keys import export_private_key
    pem = export_private_key(patient_private_key)

    return jwt.encode(payload, pem, algorithm="EdDSA")


def verify_authorization_jwt(
    token: str,
    patient_public_key: Ed25519PublicKey,
    revocation_set: Optional[Set[str]] = None,
) -> Optional[dict]:
    """验证 PHDS 授权 JWT。

    校验内容:
      1. EdDSA 签名有效性
      2. 过期时间
      3. 签发者正确
      4. 未在撤销列表中

    Args:
        token:              JWT 字符串
        patient_public_key: 患者公钥
        revocation_set:     已撤销的 jti 集合

    Returns:
        载荷字典；验证失败返回 None
    """
    from .keys import export_public_key
    pem = export_public_key(patient_public_key)

    try:
        payload = jwt.decode(
            token,
            pem,
            algorithms=["EdDSA"],
            options={"require": ["exp", "sub", "jti", "iss"]},
        )
    except jwt.InvalidTokenError:
        return None

    # 检查签发者
    if payload.get("iss") != ISSUER:
        return None

    # 检查是否已撤销
    if revocation_set and payload["jti"] in revocation_set:
        return None

    return payload


# ============================================================
# 本地撤销列表
# ============================================================

def load_revocation_set(filepath: str = DEFAULT_REVOCATION_FILE) -> Set[str]:
    """从本地文件加载已撤销 JWT ID 集合。

    Args:
        filepath: 撤销列表 JSON 文件路径

    Returns:
        已撤销 jti 集合
    """
    if not os.path.exists(filepath):
        return set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return set(data.get("revoked_jtis", []))
    except (json.JSONDecodeError, OSError):
        return set()


def save_revocation_set(revoked: Set[str], filepath: str = DEFAULT_REVOCATION_FILE) -> None:
    """将撤销列表持久化到本地文件。

    Args:
        revoked:  已撤销 jti 集合
        filepath: 输出路径
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump({"revoked_jtis": list(revoked)}, f, indent=2, ensure_ascii=False)


def revoke_authorization(
    token: str,
    patient_public_key: Ed25519PublicKey,
    filepath: str = DEFAULT_REVOCATION_FILE,
) -> bool:
    """撤销指定 JWT 的授权。

    先验证 JWT 有效性，再将其 jti 加入本地撤销列表。

    Args:
        token:              待撤销的 JWT
        patient_public_key:  患者公钥
        filepath:           撤销列表存储路径

    Returns:
        True 表示撤销成功，False 表示 JWT 无效
    """
    payload = verify_authorization_jwt(token, patient_public_key)
    if payload is None:
        return False

    revoked = load_revocation_set(filepath)
    revoked.add(payload["jti"])
    save_revocation_set(revoked, filepath)
    return True


# ============================================================
# 授权日志
# ============================================================

@dataclass
class AuthorizationLogEntry:
    """单条授权日志记录。

    Attributes:
        event_id:    事件唯一 ID
        timestamp:   事件时间（Unix 时间戳）
        action:      动作类型: "request" | "approve" | "revoke" | "expire"
        requester_id: 请求方标识
        patient_hash: 患者公钥哈希
        jti:          JWT ID（approve/revoke 时有效）
        scope:        权限范围
        expire_at:    过期时间戳
    """
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    action: str = ""
    requester_id: str = ""
    patient_hash: str = ""
    jti: str = ""
    scope: str = "read"
    expire_at: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "requester_id": self.requester_id,
            "patient_hash": self.patient_hash,
            "jti": self.jti,
            "scope": self.scope,
            "expire_at": self.expire_at,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "AuthorizationLogEntry":
        return cls(**{k: d.get(k, "") for k in [
            "event_id", "timestamp", "action", "requester_id",
            "patient_hash", "jti", "scope", "expire_at",
        ]})


class AuthorizationLog:
    """授权日志管理器。

    以追加方式写入本地 JSONL 文件，每条记录一行。

    用法::

        log = AuthorizationLog("/path/to/auth.log")
        log.append(entry)
        entries = log.read_all()
    """

    def __init__(self, filepath: str):
        """初始化日志管理器。

        Args:
            filepath: JSONL 日志文件路径
        """
        self.filepath = filepath
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

    def append(self, entry: AuthorizationLogEntry) -> None:
        """追加一条日志记录。

        Args:
            entry: 日志条目
        """
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")

    def read_all(self) -> List[AuthorizationLogEntry]:
        """读取全部日志记录。

        Returns:
            AuthorizationLogEntry 列表
        """
        if not os.path.exists(self.filepath):
            return []
        entries: List[AuthorizationLogEntry] = []
        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(
                            AuthorizationLogEntry.from_dict(json.loads(line))
                        )
                    except json.JSONDecodeError:
                        continue
        return entries
