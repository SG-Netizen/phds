"""
PHDS 加密/解密模块

核心加密方案：
  - AES-256-GCM: 对称加密，用于病历数据加解密
  - ECIES 风格混合加密:
      1. 生成临时 ECDH 密钥对（Ed25519 → X25519 转换）
      2. 与接收方公钥进行 ECDH 协商 → 共享密钥
      3. 共享密钥派生为 AES 密钥
      4. 用 AES-256-GCM 加密数据

文件加密辅助：提供对任意文件的加密/解密便捷函数。
"""
from __future__ import annotations

import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# AES-GCM 随机 Nonce 长度（12 字节，推荐值）
NONCE_LENGTH = 12
# AES-256 密钥长度
KEY_LENGTH = 32


# ============================================================
# AES-256-GCM 对称加密
# ============================================================

def generate_aes_key() -> bytes:
    """生成随机 AES-256 密钥。

    Returns:
        32 字节随机密钥
    """
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """使用 AES-256-GCM 加密数据。

    密文格式: nonce(12) || ciphertext+tag

    Args:
        key:       32 字节 AES 密钥
        plaintext: 明文数据

    Returns:
        密文（nonce + 密文+tag）
    """
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """使用 AES-256-GCM 解密数据。

    密文格式: nonce(12) || ciphertext+tag

    Args:
        key:        32 字节 AES 密钥
        ciphertext: 密文

    Returns:
        明文数据

    Raises:
        cryptography.exceptions.InvalidTag: 认证失败（密钥错误或数据被篡改）
    """
    nonce = ciphertext[:NONCE_LENGTH]
    ct = ciphertext[NONCE_LENGTH:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ============================================================
# ECIES 风格混合加密（Ed25519 → X25519 曲线转换）
# ============================================================

def _ed25519_to_curve25519_private(ed_private_bytes: bytes) -> bytes:
    """将 Ed25519 私钥种子转换为 X25519 私钥。

    转换步骤（RFC 8032 / RFC 7748）:
      1. SHA-512(seed)，取前 32 字节
      2. 对私钥标量进行 clamping（X25519 规范要求）

    Args:
        ed_private_bytes: Ed25519 私钥的 32 字节种子

    Returns:
        X25519 私钥对象
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    # SHA-512 哈希后取前 32 字节
    hashed = hashes.Hash(hashes.SHA512())
    hashed.update(ed_private_bytes)
    h = bytearray(hashed.finalize()[:32])

    # X25519 clamping: 清除低位 3 bits，设置高位 bit，清除最高位 bit
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64

    return X25519PrivateKey.from_private_bytes(bytes(h))


_CURVE25519_P = 2**255 - 19


def _ed25519_to_curve25519_public(ed_public_bytes: bytes) -> bytes:
    """通过双有理映射将 Ed25519 公钥转换为 Curve25519 (Montgomery) u 坐标。

    Ed25519 公钥是压缩的 y 坐标（含符号位）；Curve25519 使用 Montgomery u 坐标。
    映射公式: u = (1 + y) / (1 - y) mod (2^255 - 19)

    Args:
        ed_public_bytes: Ed25519 公钥 32 字节

    Returns:
        X25519 公钥对象
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    y = int.from_bytes(ed_public_bytes, "little")
    # 清除符号位（bit 255）
    y &= (1 << 255) - 1

    # 边界检查：y=1 时 (1-y) = 0，会导致除零
    if int.from_bytes(ed_public_bytes, "little") == 1:
        raise ValueError("无效的 Ed25519 公钥：y坐标等于1导致除零")

    # u = (1 + y) * (1 - y)^(-1) mod p
    p = 2**255 - 19
    u = ((1 + y) * pow(1 - y, -1, p)) % p

    return X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))


def encrypt_for_recipient(
    recipient_public_bytes: bytes,
    plaintext: bytes,
    sender_private_bytes: bytes,
) -> bytes:
    """ECIES 风格混合加密。

    流程:
      1. 将发送方 Ed25519 私钥→X25519 私钥，接收方 Ed25519 公钥→X25519 公钥
      2. ECDH 协商共享密钥
      3. HKDF 派生 AES-256 密钥
      4. AES-256-GCM 加密

    密文格式: sender_ephemeral_pub(32) || nonce(12) || ciphertext+tag

    Args:
        recipient_public_bytes: 接收方 Ed25519 公钥原始字节（32 字节）
        plaintext:              明文数据
        sender_private_bytes:   发送方 Ed25519 私钥原始字节（32 字节）

    Returns:
        密文
    """
    sender_xpriv = _ed25519_to_curve25519_private(sender_private_bytes)
    recipient_xpub = _ed25519_to_curve25519_public(recipient_public_bytes)

    # ECDH 协商
    shared_key = sender_xpriv.exchange(recipient_xpub)

    # HKDF 派生 AES 密钥
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=b"phds-ecies-v1",
    ).derive(shared_key)

    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(derived)
    ct = aesgcm.encrypt(nonce, plaintext, None)

    # 输出: 发送方临时公钥 + nonce + 密文
    sender_pub_bytes = sender_xpriv.public_key().public_bytes_raw()
    return sender_pub_bytes + nonce + ct


def decrypt_from_sender(
    recipient_private_bytes: bytes,
    ciphertext: bytes,
) -> bytes:
    """ECIES 风格混合解密。

    密文格式: sender_ephemeral_pub(32) || nonce(12) || ciphertext+tag

    Args:
        recipient_private_bytes: 接收方 Ed25519 私钥原始字节（32 字节）
        ciphertext:              密文

    Returns:
        明文数据

    Raises:
        ValueError: 密文长度不足
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    if len(ciphertext) < 32 + NONCE_LENGTH + 16:
        raise ValueError("密文长度不足")

    sender_pub_bytes = ciphertext[:32]
    nonce = ciphertext[32 : 32 + NONCE_LENGTH]
    ct = ciphertext[32 + NONCE_LENGTH :]

    recipient_xpriv = _ed25519_to_curve25519_private(recipient_private_bytes)
    sender_xpub = X25519PublicKey.from_public_bytes(sender_pub_bytes)

    shared_key = recipient_xpriv.exchange(sender_xpub)

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=b"phds-ecies-v1",
    ).derive(shared_key)

    aesgcm = AESGCM(derived)
    return aesgcm.decrypt(nonce, ct, None)


# ============================================================
# 文件加密/解密辅助
# ============================================================

def encrypt_file(key: bytes, input_path: str, output_path: str) -> None:
    """加密文件，将密文写入 output_path。

    Args:
        key:        32 字节 AES 密钥
        input_path: 明文文件路径
        output_path: 密文输出路径
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ciphertext = aes_encrypt(key, plaintext)
    with open(output_path, "wb") as f:
        f.write(ciphertext)


def decrypt_file(key: bytes, input_path: str, output_path: str) -> None:
    """解密文件，将明文写入 output_path。

    Args:
        key:        32 字节 AES 密钥
        input_path: 密文文件路径
        output_path: 明文输出路径
    """
    with open(input_path, "rb") as f:
        ciphertext = f.read()
    plaintext = aes_decrypt(key, ciphertext)
    with open(output_path, "wb") as f:
        f.write(plaintext)
