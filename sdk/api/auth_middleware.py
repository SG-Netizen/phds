"""
PHDS API 认证中间件

基于 JWT Bearer Token 的认证中间件，使用 FastAPI Depends 依赖注入：
  - 从 Authorization 头提取 Bearer token
  - 用 auth.py 中的 verify_jwt 验证
  - 验证失败返回 401
  - 提供 /token 接口用于签发 API 访问令牌
"""
from __future__ import annotations

from typing import Optional, Tuple

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.keys import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    export_private_key,
    export_public_key,
    generate_keypair,
    load_public_key,
    public_key_hash,
)
from ..core.auth import (
    create_authorization_jwt,
    verify_authorization_jwt,
    ISSUER,
    DEFAULT_EXPIRE_SECONDS,
)

# ── 预置服务端密钥对（启动时生成，用于签发 API 访问令牌）──────────
_server_pub: Optional[Ed25519PublicKey] = None
_server_priv: Optional[Ed25519PrivateKey] = None


def get_server_key_pair() -> Tuple[Ed25519PublicKey, Ed25519PrivateKey]:
    """获取或生成服务端密钥对（单例）。

    Returns:
        (公钥, 私钥) 元组
    """
    global _server_pub, _server_priv
    if _server_pub is None or _server_priv is None:
        _server_pub, _server_priv = generate_keypair()
    return _server_pub, _server_priv


def get_server_public_pem() -> str:
    """获取服务端公钥 PEM 字符串。

    Returns:
        PEM 格式公钥
    """
    pub, _ = get_server_key_pair()
    return export_public_key(pub)


# ── Bearer Token 安全方案 ──────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=False)


async def verify_api_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> str:
    """验证 API 访问令牌（FastAPI Depends）。

    从 Authorization 头提取 Bearer token，用服务端公钥验证 JWT。

    Args:
        request:     FastAPI Request 对象
        credentials: HTTPBearer 提取的凭证

    Returns:
        验证通过时返回 subject（令牌持有者标识）

    Raises:
        HTTPException: 401 认证失败
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="缺少 Authorization 头，请提供 Bearer token")

    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token 为空")

    pub, _ = get_server_key_pair()
    payload = verify_authorization_jwt(token, pub)

    if payload is None:
        raise HTTPException(status_code=401, detail="token 无效或已过期")

    # 将 subject 存入 request.state 供下游使用
    request.state.token_subject = payload.get("sub", "")
    return payload["sub"]


def create_api_token(
    subject: str,
    scope: str = "api_access",
    expire_seconds: int = DEFAULT_EXPIRE_SECONDS,
) -> str:
    """签发 API 访问令牌。

    用服务端密钥对签发 JWT，客户端凭此令牌访问受保护接口。

    Args:
        subject:        令牌持有者标识（如应用 ID）
        scope:          权限范围，默认 "api_access"
        expire_seconds: 有效期（秒），默认 3600

    Returns:
        JWT 字符串
    """
    pub, priv = get_server_key_pair()
    return create_authorization_jwt(
        patient_private_key=priv,
        patient_public_key=pub,
        requester_id=subject,
        scope=scope,
        expire_seconds=expire_seconds,
    )


# ── 对外暴露的依赖函数 ────────────────────────────────────
get_current_user = verify_api_token
"""FastAPI Depends 依赖函数，对外暴露的标准名称。

用法::

    @app.get("/protected")
    def protected_endpoint(subject: str = Depends(get_current_user)):
        ...
"""
