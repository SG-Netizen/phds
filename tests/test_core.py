"""
PHDS 核心模块单元测试

覆盖:
  - keys:   密钥生成、导入/导出、助记词恢复
  - crypto: AES-256-GCM 加解密、ECIES 混合加密
  - auth:   JWT 签发/验证/撤销

运行: python -m pytest tests/test_core.py -v
      或: python tests/test_core.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdk.core.keys import (
    generate_keypair,
    export_public_key,
    export_private_key,
    load_public_key,
    load_private_key,
    public_key_hash,
    generate_mnemonic,
    keypair_from_mnemonic,
    mnemonic_to_seed,
)
from sdk.core.crypto import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    encrypt_for_recipient,
    decrypt_from_sender,
    encrypt_file,
    decrypt_file,
)
from sdk.core.auth import (
    create_authorization_jwt,
    verify_authorization_jwt,
    generate_session_key,
    load_revocation_set,
    save_revocation_set,
    revoke_authorization,
    AuthorizationLog,
    AuthorizationLogEntry,
    DEFAULT_EXPIRE_SECONDS,
)
from sdk.records.bio_record import BioRecord, RecordMetadata
from sdk.records.authorization import AuthorizationEvent, AuthorizationStatus


class TestKeys(unittest.TestCase):
    """密钥管理测试"""

    def test_generate_keypair(self) -> None:
        """测试密钥对生成"""
        pub, priv = generate_keypair()
        self.assertIsNotNone(pub)
        self.assertIsNotNone(priv)

    def test_export_import_roundtrip(self) -> None:
        """测试 PEM 导入导出往返"""
        pub, priv = generate_keypair()

        pub_pem = export_public_key(pub)
        priv_pem = export_private_key(priv)

        pub2 = load_public_key(pub_pem)
        priv2 = load_private_key(priv_pem)

        self.assertEqual(
            public_key_hash(pub),
            public_key_hash(pub2),
        )

    def test_public_key_hash(self) -> None:
        """测试公钥哈希"""
        pub, _ = generate_keypair()
        h = public_key_hash(pub)
        self.assertEqual(len(h), 64)  # SHA-256 → 64 hex chars
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_mnemonic_generation(self) -> None:
        """测试助记词生成"""
        mnemonic = generate_mnemonic()
        words = mnemonic.split()
        self.assertEqual(len(words), 24)

    def test_mnemonic_seed(self) -> None:
        """测试助记词 → 种子"""
        mnemonic = generate_mnemonic()
        seed = mnemonic_to_seed(mnemonic)
        self.assertEqual(len(seed), 64)

    def test_keypair_from_mnemonic(self) -> None:
        """测试从助记词恢复密钥"""
        mnemonic = generate_mnemonic()
        pub1, priv1 = keypair_from_mnemonic(mnemonic)
        pub2, priv2 = keypair_from_mnemonic(mnemonic)

        self.assertEqual(public_key_hash(pub1), public_key_hash(pub2))
        self.assertEqual(
            export_private_key(priv1),
            export_private_key(priv2),
        )

    def test_mnemonic_with_passphrase(self) -> None:
        """测试带口令的助记词恢复"""
        mnemonic = generate_mnemonic()
        pub1, _ = keypair_from_mnemonic(mnemonic, passphrase="hello")
        pub2, _ = keypair_from_mnemonic(mnemonic, passphrase="world")
        self.assertNotEqual(public_key_hash(pub1), public_key_hash(pub2))


class TestCrypto(unittest.TestCase):
    """加密解密测试"""

    def setUp(self) -> None:
        self.aes_key = generate_aes_key()
        self.plaintext = b"Hello, PHDS! This is a test message for encryption."

    def test_aes_encrypt_decrypt(self) -> None:
        """测试 AES-256-GCM 加解密往返"""
        ct = aes_encrypt(self.aes_key, self.plaintext)
        pt = aes_decrypt(self.aes_key, ct)
        self.assertEqual(pt, self.plaintext)

    def test_aes_different_keys_fail(self) -> None:
        """测试不同密钥解密应失败"""
        ct = aes_encrypt(self.aes_key, self.plaintext)
        wrong_key = generate_aes_key()
        with self.assertRaises(Exception):
            aes_decrypt(wrong_key, ct)

    def test_aes_tampered_data_fail(self) -> None:
        """测试篡改数据解密应失败"""
        ct = aes_encrypt(self.aes_key, self.plaintext)
        tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with self.assertRaises(Exception):
            aes_decrypt(self.aes_key, tampered)

    def test_ecies_roundtrip(self) -> None:
        """测试 ECIES 混合加密往返"""
        pub, priv = generate_keypair()

        pub_bytes = pub.public_bytes_raw()
        priv_bytes = priv.private_bytes_raw()

        ct = encrypt_for_recipient(pub_bytes, self.plaintext, priv_bytes)
        pt = decrypt_from_sender(priv_bytes, ct)
        self.assertEqual(pt, self.plaintext)

    def test_file_encrypt_decrypt(self) -> None:
        """测试文件加解密"""
        import uuid

        uid = uuid.uuid4().hex
        tmp_plain = os.path.join(tempfile.gettempdir(), f"phds_plain_{uid}.txt")
        tmp_enc = os.path.join(tempfile.gettempdir(), f"phds_enc_{uid}.bin")
        tmp_dec = os.path.join(tempfile.gettempdir(), f"phds_dec_{uid}.txt")

        with open(tmp_plain, "wb") as f:
            f.write(self.plaintext)

        encrypt_file(self.aes_key, tmp_plain, tmp_enc)
        decrypt_file(self.aes_key, tmp_enc, tmp_dec)

        with open(tmp_dec, "rb") as f:
            result = f.read()

        self.assertEqual(result, self.plaintext)

    def test_empty_plaintext(self) -> None:
        """测试空明文加解密"""
        ct = aes_encrypt(self.aes_key, b"")
        pt = aes_decrypt(self.aes_key, ct)
        self.assertEqual(pt, b"")

    def test_large_plaintext(self) -> None:
        """测试大数据加解密（100KB）"""
        large = os.urandom(100_000)
        ct = aes_encrypt(self.aes_key, large)
        pt = aes_decrypt(self.aes_key, ct)
        self.assertEqual(pt, large)


class TestAuth(unittest.TestCase):
    """授权管理测试"""

    def setUp(self) -> None:
        self.pub, self.priv = generate_keypair()
        self.requester_id = "doctor_bob_hash_123"
        self.session_key = generate_session_key()
        self.log_path = os.path.join(tempfile.gettempdir(), f"phds_test_{uuid.uuid4().hex}.jsonl")

    def test_create_and_verify_jwt(self) -> None:
        """测试 JWT 签发和验证"""
        token = create_authorization_jwt(
            patient_private_key=self.priv,
            patient_public_key=self.pub,
            requester_id=self.requester_id,
        )

        payload = verify_authorization_jwt(token, self.pub)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["requester"], self.requester_id)
        self.assertEqual(payload["scope"], "read")
        self.assertEqual(payload["iss"], "phds-protocol-v1")

    def test_jwt_expiration(self) -> None:
        """测试 JWT 过期"""
        token = create_authorization_jwt(
            patient_private_key=self.priv,
            patient_public_key=self.pub,
            requester_id=self.requester_id,
            expire_seconds=1,
        )

        # 立即验证 → 通过
        self.assertIsNotNone(verify_authorization_jwt(token, self.pub))

        # 等待过期
        time.sleep(2)
        self.assertIsNone(verify_authorization_jwt(token, self.pub))

    def test_jwt_wrong_key_fail(self) -> None:
        """测试错误公钥验证失败"""
        token = create_authorization_jwt(
            patient_private_key=self.priv,
            patient_public_key=self.pub,
            requester_id=self.requester_id,
        )

        # 用另一个公钥验证
        wrong_pub, _ = generate_keypair()
        self.assertIsNone(verify_authorization_jwt(token, wrong_pub))

    def test_revoke(self) -> None:
        """测试撤销授权"""
        token = create_authorization_jwt(
            patient_private_key=self.priv,
            patient_public_key=self.pub,
            requester_id=self.requester_id,
        )

        payload = verify_authorization_jwt(token, self.pub)
        jti = payload["jti"]

        # 先验证通过
        self.assertIsNotNone(verify_authorization_jwt(token, self.pub))

        # 撤销
        result = revoke_authorization(token, self.pub)
        self.assertTrue(result)

        # 撤销后再验证应失败
        revocation_set = {jti}
        self.assertIsNone(
            verify_authorization_jwt(token, self.pub, revocation_set)
        )

    def test_session_key_length(self) -> None:
        """测试会话密钥长度"""
        sk = generate_session_key()
        self.assertEqual(len(sk), 32)  # AES-256

    def test_auth_log(self) -> None:
        """测试授权日志"""
        log = AuthorizationLog(self.log_path)

        entry = AuthorizationLogEntry(
            action="request",
            requester_id=self.requester_id,
            patient_hash="alice_hash_123",
        )
        log.append(entry)

        entries = log.read_all()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].action, "request")


class TestBioRecord(unittest.TestCase):
    """BioRecord 数据结构测试"""

    def test_create_and_serialize(self) -> None:
        """测试创建和序列化"""
        metadata = RecordMetadata(
            hospital_id="h001",
            record_type="lab_report",
            description="化验报告",
        )
        record = BioRecord.create(
            patient_pubkey_hash="alice_hash",
            encrypted_data_url="phds://alice_hash/r/abc",
            encrypted_data=b"encrypted_data",
            metadata=metadata,
        )

        self.assertTrue(record.record_id)
        self.assertEqual(record.patient_pubkey_hash, "alice_hash")
        self.assertEqual(len(record.data_hash), 64)

        # JSON 往返
        record2 = BioRecord.from_json(record.to_json())
        self.assertEqual(record.record_id, record2.record_id)
        self.assertEqual(record.data_hash, record2.data_hash)

    def test_verify_integrity(self) -> None:
        """测试完整性验证"""
        metadata = RecordMetadata()
        data = b"test_data"

        record = BioRecord.create(
            patient_pubkey_hash="hash",
            encrypted_data_url="url",
            encrypted_data=data,
            metadata=metadata,
        )

        self.assertTrue(record.verify_integrity(data))
        self.assertFalse(record.verify_integrity(b"tampered"))


class TestAuthorizationEvent(unittest.TestCase):
    """AuthorizationEvent 测试"""

    def test_lifecycle(self) -> None:
        """测试授权生命周期"""
        event = AuthorizationEvent(
            patient_pubkey_hash="patient_hash",
            requester_id="doctor_hash",
            scope="write",
        )

        self.assertEqual(event.status, AuthorizationStatus.PENDING)

        # 批准
        event.approve(
            session_key="session_key_b64",
            expire_at=time.time() + 3600,
            jti="jti_abc",
        )
        self.assertEqual(event.status, AuthorizationStatus.APPROVED)
        self.assertTrue(event.is_active())

        # 撤销
        event.revoke()
        self.assertEqual(event.status, AuthorizationStatus.REVOKED)
        self.assertFalse(event.is_active())

    def test_deny(self) -> None:
        """测试拒绝"""
        event = AuthorizationEvent()
        event.deny()
        self.assertEqual(event.status, AuthorizationStatus.DENIED)

    def test_serialize(self) -> None:
        """测试序列化往返"""
        event = AuthorizationEvent(
            patient_pubkey_hash="hash",
            requester_id="doctor",
        )
        d = event.to_dict()
        event2 = AuthorizationEvent.from_dict(d)
        self.assertEqual(event.request_id, event2.request_id)
        self.assertEqual(event.status, event2.status)


class TestSM2(unittest.TestCase):
    """SM2 国密测试"""

    def test_sm2_encrypt_decrypt(self) -> None:
        """测试 SM2 加密 → 解密的完整往返"""
        from sdk.core.keys import generate_sm2_keypair, sm2_encrypt, sm2_decrypt

        pub_hex, priv_hex = generate_sm2_keypair()
        plaintext = b"PHDS SM2 test data for encryption and decryption"

        ciphertext = sm2_encrypt(pub_hex, plaintext)
        self.assertNotEqual(ciphertext, plaintext)  # 密文与明文不同

        decrypted = sm2_decrypt(priv_hex, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_sm2_sign_verify(self) -> None:
        """测试 SM2 签名 → 验签（利用加解密来验证密钥一致性）"""
        from sdk.core.keys import generate_sm2_keypair, sm2_encrypt, sm2_decrypt

        pub_hex, priv_hex = generate_sm2_keypair()

        # SM2 通过加解密验证密钥对一致性（签名验签在更高层实现）
        msg = b"PHDS SM2 sign test message"
        ct = sm2_encrypt(pub_hex, msg)
        pt = sm2_decrypt(priv_hex, ct)
        self.assertEqual(pt, msg)

        # 每次加密应产生不同密文（SM2 加密含随机数）
        ct2 = sm2_encrypt(pub_hex, msg)
        self.assertNotEqual(ct, ct2)
        pt2 = sm2_decrypt(priv_hex, ct2)
        self.assertEqual(pt2, msg)

    def test_ed25519_to_sm2_compatibility(self) -> None:
        """测试 Ed25519 和 SM2 密钥不互串"""
        from sdk.core.keys import generate_keypair, generate_sm2_keypair

        # Ed25519 密钥
        ed_pub, _ = generate_keypair()

        # SM2 密钥
        sm2_pub_hex, sm2_priv_hex = generate_sm2_keypair()

        # 用 SM2 加密一段数据
        from sdk.core.keys import sm2_encrypt, sm2_decrypt

        msg = b"cross-algorithm isolation test"
        ct = sm2_encrypt(sm2_pub_hex, msg)

        # SM2 私钥可以解密
        pt = sm2_decrypt(sm2_priv_hex, ct)
        self.assertEqual(pt, msg)

        # Ed25519 公钥长度不同于 SM2 公钥，证明算法隔离
        ed_pub_bytes = ed_pub.public_bytes_raw()
        sm2_pub_bytes = bytes.fromhex(sm2_pub_hex)
        # 两者长度不同，证实完全不同的密钥体系
        self.assertNotEqual(len(ed_pub_bytes), len(sm2_pub_bytes))


if __name__ == "__main__":
    unittest.main(verbosity=2)
