"""
PHDS 简化密钥管理模式（"简化患者模式"）

用户用手机号/微信 OpenID + 6 位 PIN 即可自动派生密钥对，
无需管理助记词或私钥文件。

设计方案：确定性密钥派生（Deterministic Key Derivation）

    用户手机号/OpenID + 用户自设PIN + 固定盐值
      → PBKDF2-HMAC-SHA256 (10 万次迭代)
      → 64 字节种子
      → 前 32 字节作为 Ed25519 私钥种子
      → 后 32 字节作为 SM2 私钥种子

特性:
  - 不存储私钥，每次登录重新派生
  - 用户只需记住 6 位 PIN
  - 换设备后输入手机号+PIN 即可恢复
  - 使用 cryptography 库的 PBKDF2，无需新增依赖

用法::

    from sdk.core.lite_keys import derive_keypair, verify_pin

    pub, priv = derive_keypair("13800138000", "123456")
    assert verify_pin("13800138000", "123456", pub) is True
"""
from __future__ import annotations

import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .keys import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    export_public_key,
    export_private_key,
    public_key_hash,
)

# ── 常量 ────────────────────────────────────────────────────
# PBKDF2 迭代次数（10 万次，平衡安全性与性能）
PBKDF2_ITERATIONS = 100_000
# 派生种子长度（前 32 字节 Ed25519，后 32 字节 SM2）
DERIVED_KEY_LENGTH = 64
# 固定盐值前缀（PHDS v1 协议标识，确保不同应用间密钥隔离）
FIXED_SALT_PREFIX = b"phds-lite-v1:"


def _derive_seed(user_id: str, pin: str) -> bytes:
    """从用户标识和 PIN 派生 64 字节种子。

    核心派生链:
      PBKDF2-HMAC-SHA256(
        password = user_id + ":" + pin,
        salt = FIXED_SALT_PREFIX + SHA256(user_id)[:16],
        iterations = 100000,
        length = 64
      )

    Args:
        user_id: 用户唯一标识（手机号 / OpenID / 邮箱等）
        pin:     用户自设的 6 位 PIN

    Returns:
        64 字节确定性种子
    """
    # 用户标识哈希作为个性化盐值的一部分
    user_hash = hashlib.sha256(user_id.encode("utf-8")).digest()[:16]

    # 拼接 salt = 固定前缀 + 用户标识哈希前 16 字节
    salt = FIXED_SALT_PREFIX + user_hash

    # 拼接 password = user_id + ":" + pin
    password = f"{user_id}:{pin}".encode("utf-8")

    # PBKDF2 派生
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password)


def derive_keypair(
    user_id: str,
    pin: str,
) -> Tuple[Ed25519PublicKey, Ed25519PrivateKey]:
    """从用户标识 + PIN 确定性派生 Ed25519 密钥对。

    每次使用相同的 user_id 和 pin 调用，生成完全相同的密钥对。

    Args:
        user_id: 用户唯一标识（手机号/OpenID/邮箱等）
        pin:     用户自设的 PIN（建议 6 位数字）

    Returns:
        (公钥, 私钥) 元组

    Raises:
        ValueError: user_id 或 pin 为空
    """
    if not user_id or not user_id.strip():
        raise ValueError("user_id 不能为空")
    if not pin or not pin.strip():
        raise ValueError("PIN 不能为空")

    seed = _derive_seed(user_id.strip(), pin.strip())
    # 前 32 字节作为 Ed25519 私钥种子
    private_key = Ed25519PrivateKey.from_private_bytes(seed[:32])
    return private_key.public_key(), private_key


def derive_sm2_keypair(user_id: str, pin: str) -> Tuple[str, str]:
    """从用户标识 + PIN 确定性派生 SM2 密钥对（国密）。

    Args:
        user_id: 用户唯一标识
        pin:     用户自设的 PIN

    Returns:
        (SM2公钥hex, SM2私钥hex) 元组
    """
    seed = _derive_seed(user_id, pin)

    # 后 32 字节作为 SM2 私钥（hex）
    private_key_hex = seed[32:].hex()

    # 通过椭圆曲线计算公钥
    from gmssl import sm2

    crypt = sm2.CryptSM2(private_key=private_key_hex, public_key="")
    public_key_hex = crypt._kg(
        int(private_key_hex, 16), sm2.default_ecc_table["g"]
    )

    return public_key_hex, private_key_hex


def verify_pin(
    user_id: str,
    pin: str,
    expected_public_key: Ed25519PublicKey,
) -> bool:
    """验证用户 PIN 是否正确。

    使用派生出的公钥与预期公钥比对，不暴露私钥。

    Args:
        user_id:             用户唯一标识
        pin:                 待验证的 PIN
        expected_public_key: 预期正确的公钥对象

    Returns:
        True 表示 PIN 正确
    """
    try:
        derived_pub, _ = derive_keypair(user_id, pin)
    except ValueError:
        return False
    return public_key_hash(derived_pub) == public_key_hash(expected_public_key)


def get_public_key_hash(user_id: str, pin: str) -> str:
    """获取用户公钥哈希（匿名标识），无需持有密钥对象。

    Args:
        user_id: 用户唯一标识
        pin:     用户 PIN

    Returns:
        64 字符十六进制公钥哈希
    """
    pub, _ = derive_keypair(user_id, pin)
    return public_key_hash(pub)
