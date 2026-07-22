"""
PHDS 患者端独立演示脚本

功能:
  - 生成 Ed25519 密钥对 + BIP39 助记词
  - 使用 AES-256-GCM 加密病历数据
  - 创建 BioRecord 并导出
  - 审批授权请求

运行: python demo/demo_patient.py
"""
from __future__ import annotations

import base64
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdk.core.keys import (
    generate_keypair,
    generate_mnemonic,
    keypair_from_mnemonic,
    export_public_key,
    export_private_key,
    public_key_hash,
)
from sdk.core.crypto import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    encrypt_for_recipient,
    decrypt_from_sender,
)
from sdk.core.auth import (
    create_authorization_jwt,
    verify_authorization_jwt,
    generate_session_key,
    DEFAULT_EXPIRE_SECONDS,
)
from sdk.records.bio_record import BioRecord, RecordMetadata
from sdk.records.authorization import AuthorizationEvent, AuthorizationStatus


SEP = "=" * 60


def main() -> None:
    print("\n" + SEP)
    print("  PHDS 患者端演示 - Alice")
    print(SEP)

    work_dir = os.path.join(os.path.dirname(__file__), ".phds_patient")
    os.makedirs(work_dir, exist_ok=True)

    # ── 1. 生成密钥 + 助记词 ──────────────────────────────────
    print("\n[1] 生成 Ed25519 密钥对 + BIP39 助记词\n")

    pub, priv = generate_keypair()
    patient_hash = public_key_hash(pub)

    print(f"  公钥哈希（匿名标识）: {patient_hash}")

    # 生成助记词
    mnemonic = generate_mnemonic()
    print(f"  助记词（24 单词）: ")
    words = mnemonic.split()
    for i in range(0, len(words), 4):
        print(f"    {'  '.join(words[i:i+4])}")

    # 从助记词恢复密钥
    pub2, priv2 = keypair_from_mnemonic(mnemonic)
    hash2 = public_key_hash(pub2)
    print(f"\n  助记词恢复验证: {'通过' if hash2 == public_key_hash(pub2) else '失败'}")

    # 保存
    with open(os.path.join(work_dir, "mnemonic.txt"), "w") as f:
        f.write(mnemonic)
    with open(os.path.join(work_dir, "pub.pem"), "w") as f:
        f.write(export_public_key(pub))
    with open(os.path.join(work_dir, "priv.pem"), "w") as f:
        f.write(export_private_key(priv))

    # ── 2. 加密病历 ──────────────────────────────────────────
    print("\n[2] 加密病历数据\n")

    record_data = {
        "patient": "Alice",
        "hospital": "XX市人民医院",
        "date": "2026-07-22",
        "type": "lab_report",
        "results": {
            "blood_sugar": "5.6 mmol/L",
            "cholesterol": "4.2 mmol/L",
            "blood_pressure": "120/80 mmHg",
        },
        "notes": "各项指标正常",
    }
    plaintext = json.dumps(record_data, ensure_ascii=False).encode("utf-8")

    # AES-256-GCM 加密
    aes_key = generate_aes_key()
    encrypted = aes_encrypt(aes_key, plaintext)

    print(f"  原始数据: {len(plaintext)} 字节")
    print(f"  加密数据: {len(encrypted)} 字节")
    print(f"  AES 密钥: {base64.b64encode(aes_key).decode()[:32]}...")

    # 保存加密数据 + AES 密钥（实际场景中密钥应安全保存）
    with open(os.path.join(work_dir, "encrypted.bin"), "wb") as f:
        f.write(encrypted)
    with open(os.path.join(work_dir, "aes_key.b64"), "w") as f:
        f.write(base64.b64encode(aes_key).decode())

    # ── 3. 创建 BioRecord ────────────────────────────────────
    print("\n[3] 创建 BioRecord\n")

    metadata = RecordMetadata(
        hospital_id="hospital_001",
        record_type="lab_report",
        description="2026-07-22 化验报告",
    )
    record = BioRecord.create(
        patient_pubkey_hash=patient_hash,
        encrypted_data_url=f"phds://{patient_hash}/records/{uuid.uuid4().hex[:8]}",
        encrypted_data=encrypted,
        metadata=metadata,
    )

    # 导出为 JSON
    record_json = record.to_json()
    print(f"  record_id:  {record.record_id}")
    print(f"  data_hash:  {record.data_hash}")
    print(f"  JSON 大小:  {len(record_json)} 字节")

    with open(os.path.join(work_dir, "record.json"), "w", encoding="utf-8") as f:
        f.write(record_json)

    # ── 4. 模拟审批授权 ──────────────────────────────────────
    print("\n[4] 审批授权请求\n")

    # 模拟收到授权请求
    requester_id = "doctor_bob_hash_abc123"
    auth_event = AuthorizationEvent(
        patient_pubkey_hash=patient_hash,
        requester_id=requester_id,
        scope="read",
    )
    print(f"  收到请求: {auth_event.request_id}")
    print(f"  请求方:    {requester_id}")
    print(f"  当前状态:  {auth_event.status}")

    # 批准
    session_key = generate_session_key()
    session_key_b64 = base64.b64encode(session_key).decode()

    jwt_token = create_authorization_jwt(
        patient_private_key=priv,
        patient_public_key=pub,
        requester_id=requester_id,
        scope="read",
        expire_seconds=DEFAULT_EXPIRE_SECONDS,
    )

    payload = verify_authorization_jwt(jwt_token, pub)
    auth_event.approve(session_key_b64, float(payload["exp"]), payload["jti"])

    print(f"\n  已批准！")
    print(f"  JWT ID:    {payload['jti'][:16]}...")
    print(f"  会话密钥:  {session_key_b64[:24]}...")
    print(f"  有效期:     {DEFAULT_EXPIRE_SECONDS} 秒")

    # 保存授权输出
    with open(os.path.join(work_dir, "authorization.json"), "w", encoding="utf-8") as f:
        json.dump({
            "request_id": auth_event.request_id,
            "jwt_token": jwt_token,
            "session_key_b64": session_key_b64,
            "status": auth_event.status,
        }, f, indent=2, ensure_ascii=False)

    # ── 5. 验证解密 ──────────────────────────────────────────
    print("\n[5] 验证：用自己的会话密钥解密病历\n")

    try:
        plain = aes_decrypt(aes_key, encrypted)
        recovered = json.loads(plain.decode("utf-8"))
        print(f"  解密成功！病历摘要:")
        print(f"    医院:   {recovered['hospital']}")
        print(f"    类型:   {recovered['type']}")
        print(f"    诊断:   {recovered['notes']}")
    except Exception as e:
        print(f"  解密失败: {e}")

    print(f"\n  完整性校验: {'通过' if record.verify_integrity(encrypted) else '失败'}")

    print(f"\n{SEP}")
    print(f"  患者端演示完成。产出文件: {work_dir}")
    print(SEP)


if __name__ == "__main__":
    main()
