"""
PHDS 密钥管理模块

提供 Ed25519 和 SM2（国密）两种密钥方案：
  - Ed25519: 默认签名算法，用于授权 JWT 签名
  - SM2:    国密兼容，使用 gmssl 库
  - BIP39:  助记词生成与恢复

用法::

    from phds.sdk.core.keys import generate_keypair, export_private_key

    pub, priv = generate_keypair()          # Ed25519
    pem_str = export_private_key(priv)      # 导出 PEM
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from mnemonic import Mnemonic


# ── 类型别名 ────────────────────────────────────────────────
Ed25519PrivateKey = ed25519.Ed25519PrivateKey
Ed25519PublicKey = ed25519.Ed25519PublicKey

# BIP39 英文助记词，强度 256 位 → 24 个单词
_MNEMO = Mnemonic("english")


# ============================================================
# Ed25519 密钥管理
# ============================================================

def generate_keypair() -> Tuple[Ed25519PublicKey, Ed25519PrivateKey]:
    """生成 Ed25519 密钥对。

    Returns:
        (公钥, 私钥) 元组
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key.public_key(), private_key


def export_private_key(private_key: Ed25519PrivateKey) -> str:
    """将 Ed25519 私钥导出为 PEM 格式字符串。

    Args:
        private_key: Ed25519 私钥对象

    Returns:
        PEM 格式字符串（UTF-8）
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def export_public_key(public_key: Ed25519PublicKey) -> str:
    """将 Ed25519 公钥导出为 PEM 格式字符串。

    Args:
        public_key: Ed25519 公钥对象

    Returns:
        PEM 格式字符串（UTF-8）
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_private_key(pem_data: str) -> Ed25519PrivateKey:
    """从 PEM 字符串加载 Ed25519 私钥。

    Args:
        pem_data: PEM 格式私钥字符串

    Returns:
        Ed25519PrivateKey 对象
    """
    return serialization.load_pem_private_key(
        pem_data.encode("utf-8"), password=None
    )


def load_public_key(pem_data: str) -> Ed25519PublicKey:
    """从 PEM 字符串加载 Ed25519 公钥。

    Args:
        pem_data: PEM 格式公钥字符串

    Returns:
        Ed25519PublicKey 对象
    """
    return serialization.load_pem_public_key(pem_data.encode("utf-8"))


def public_key_hash(public_key: Ed25519PublicKey) -> str:
    """计算公钥的 SHA-256 哈希（十六进制），用作患者匿名标识。

    Args:
        public_key: Ed25519 公钥对象

    Returns:
        64 字符十六进制哈希字符串
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


# ============================================================
# BIP39 助记词
# ============================================================

def generate_mnemonic(strength: int = 256) -> str:
    """生成 BIP39 助记词（默认 24 个英文单词）。

    Args:
        strength: 熵强度（位），默认 256 → 24 个单词

    Returns:
        空格分隔的助记词字符串
    """
    return _MNEMO.generate(strength=strength)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """将助记词转换为 64 字节种子。

    Args:
        mnemonic:  助记词字符串
        passphrase: 可选口令

    Returns:
        64 字节种子
    """
    return _MNEMO.to_seed(mnemonic, passphrase=passphrase)


def keypair_from_mnemonic(mnemonic: str, passphrase: str = "") -> Tuple[Ed25519PublicKey, Ed25519PrivateKey]:
    """从助记词恢复 Ed25519 密钥对。

    使用前 32 字节种子作为 Ed25519 私钥种子。

    Args:
        mnemonic:   助记词字符串
        passphrase: 可选口令

    Returns:
        (公钥, 私钥) 元组
    """
    seed = mnemonic_to_seed(mnemonic, passphrase)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
    return private_key.public_key(), private_key


# ============================================================
# SM2 国密兼容（可选）
# ============================================================

def generate_sm2_keypair() -> Tuple[str, str]:
    """生成 SM2 密钥对（国密）。

    需要安装 gmssl 库：pip install gmssl

    Returns:
        (公钥_hex, 私钥_hex) 元组

    Raises:
        ImportError: 未安装 gmssl 库
    """
    try:
        from gmssl import sm2
    except ImportError:
        raise ImportError(
            "SM2 需要 gmssl 库，请运行: pip install gmssl"
        )

    # 生成 32 字节随机私钥
    private_key_hex = os.urandom(32).hex()
    # 通过椭圆曲线点乘计算公钥: pub = priv * G
    crypt = sm2.CryptSM2(private_key=private_key_hex, public_key="")
    public_key_hex = crypt._kg(int(private_key_hex, 16), sm2.default_ecc_table["g"])
    return public_key_hex, private_key_hex


def sm2_encrypt(public_key_hex: str, plaintext: bytes) -> bytes:
    """使用 SM2 公钥加密数据（C1C3C2 模式）。

    Args:
        public_key_hex: SM2 公钥（十六进制）
        plaintext:      明文数据

    Returns:
        密文
    """
    from gmssl import sm2

    crypt = sm2.CryptSM2(private_key="", public_key=public_key_hex)
    return crypt.encrypt(plaintext)


def sm2_decrypt(private_key_hex: str, ciphertext: bytes) -> bytes:
    """使用 SM2 私钥解密数据。

    Args:
        private_key_hex: SM2 私钥（十六进制）
        ciphertext:      密文

    Returns:
        明文
    """
    from gmssl import sm2

    crypt = sm2.CryptSM2(private_key=private_key_hex, public_key="")
    return crypt.decrypt(ciphertext)
