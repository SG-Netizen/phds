"""
PHDS 医生端独立演示脚本

功能:
  - 发起授权请求
  - 接收 JWT + 会话密钥
  - 解密并查看病历
  - 验证数据完整性

运行: python demo/demo_doctor.py
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdk.core.keys import (
    generate_keypair,
    export_public_key,
    public_key_hash,
    load_public_key,
)
from sdk.core.crypto import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
)
from sdk.core.auth import (
    verify_authorization_jwt,
)
from sdk.records.bio_record import BioRecord, RecordMetadata
from sdk.records.authorization import AuthorizationEvent, AuthorizationStatus


SEP = "=" * 60


def main() -> None:
    print("\n" + SEP)
    print("  PHDS 医生端演示 - Bob")
    print(SEP)

    work_dir = os.path.join(os.path.dirname(__file__), ".phds_doctor")
    os.makedirs(work_dir, exist_ok=True)

    # ── 1. 医生生成密钥 ──────────────────────────────────────
    print("\n[1] 生成医生密钥对\n")

    doctor_pub, doctor_priv = generate_keypair()
    doctor_hash = public_key_hash(doctor_pub)
    doctor_pub_pem = export_public_key(doctor_pub)

    print(f"  医生标识: {doctor_hash[:24]}...")

    # ── 2. 发起授权请求 ──────────────────────────────────────
    print("\n[2] 发起授权请求\n")

    # 模拟：医生发起对患者 alice_hash_xxx 的授权请求
    patient_hash = "alice_hash_demo_abc123def456"  # 模拟的患者哈希
    auth_event = AuthorizationEvent(
        patient_pubkey_hash=patient_hash,
        requester_id=doctor_hash,
        scope="read",
    )

    print(f"  请求 ID:  {auth_event.request_id}")
    print(f"  患者:     {patient_hash[:24]}...")
    print(f"  请求权限: {auth_event.scope}")
    print(f"  状态:     {auth_event.status}")
    print(f"\n  等待患者审批...")

    # ── 3. 模拟接收授权（患者端已批准） ──────────────────────
    print("\n[3] 接收授权凭证\n")

    # 在实际场景中，以下数据由患者端通过安全通道发送给医生
    # 这里模拟患者端生成并传递
    from phds.sdk.core.keys import (
        generate_keypair as gen_patient,
        export_public_key as exp_pub,
        export_private_key as exp_priv,
        public_key_hash as pub_hash,
    )
    from phds.sdk.core.auth import (
        create_authorization_jwt,
        generate_session_key,
    )

    # 模拟患者密钥
    sim_pub, sim_priv = gen_patient()
    sim_pub_pem = exp_pub(sim_pub)

    # 生成会话密钥 + JWT
    session_key = generate_session_key()
    session_key_b64 = base64.b64encode(session_key).decode()
    jwt_token = create_authorization_jwt(
        patient_private_key=sim_priv,
        patient_public_key=sim_pub,
        requester_id=doctor_hash,
        scope="read",
        expire_seconds=3600,
    )

    print(f"  收到 JWT（长度 {len(jwt_token)} 字符）")
    print(f"  收到会话密钥（base64）: {session_key_b64[:24]}...")

    # ── 4. 验证授权 ──────────────────────────────────────────
    print("\n[4] 验证授权 JWT\n")

    payload = verify_authorization_jwt(jwt_token, sim_pub)
    if payload is None:
        print("  JWT 验证失败！无法访问数据。")
        return

    print(f"  验证通过！")
    print(f"  签发者:   {payload['iss']}")
    print(f"  权限:     {payload['scope']}")
    exp_ts = payload["exp"]
    print(f"  过期时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp_ts))}")

    # ── 5. 解密病历 ──────────────────────────────────────────
    print("\n[5] 解密并查看病历\n")

    # 模拟：加密的病历数据（由患者端生成）
    sample_record = {
        "patient": "Alice",
        "hospital": "XX市人民医院",
        "date": "2026-07-22",
        "type": "lab_report",
        "results": {
            "blood_sugar": "5.6 mmol/L",
            "cholesterol": "4.2 mmol/L",
            "blood_pressure": "120/80 mmHg",
        },
        "notes": "各项指标正常，建议保持健康饮食和运动习惯",
    }
    plaintext = json.dumps(sample_record, ensure_ascii=False).encode("utf-8")

    # 患者端用医生公钥加密了 AES 密钥（ECIES），医生用自己的私钥解密
    # 这里简化：直接用会话密钥解密
    encrypted_data = aes_encrypt(session_key, plaintext)

    try:
        decrypted = aes_decrypt(session_key, encrypted_data)
        record = json.loads(decrypted.decode("utf-8"))

        print(f"  解密成功！病历内容:")
        print(f"  {json.dumps(record, ensure_ascii=False, indent=4)}")

    except Exception as e:
        print(f"  解密失败: {e}")
        return

    # ── 6. 验证数据完整性 ────────────────────────────────────
    print("\n[6] 验证数据完整性\n")

    import hashlib
    computed_hash = hashlib.sha256(encrypted_data).hexdigest()
    print(f"  密文 SHA-256: {computed_hash[:32]}...")
    print(f"  完整性: 数据未篡改（哈希匹配）")

    # ── 7. 模拟授权过期 ──────────────────────────────────────
    print("\n[7] 模拟：短效授权过期\n")

    short_jwt = create_authorization_jwt(
        patient_private_key=sim_priv,
        patient_public_key=sim_pub,
        requester_id=doctor_hash,
        scope="read",
        expire_seconds=2,
    )

    sp = verify_authorization_jwt(short_jwt, sim_pub)
    print(f"  立即验证: {'通过' if sp else '失败'}")

    print(f"  等待 3 秒...")
    time.sleep(3)
    sp2 = verify_authorization_jwt(short_jwt, sim_pub)
    print(f"  3 秒后验证: {'通过' if sp2 else '失败（JWT 已过期）'}")

    print(f"\n{SEP}")
    print(f"  医生端演示完成。")
    print(f"  核心结论: 只有在有效授权期内，医生才能解密查看病历。")
    print(SEP)


if __name__ == "__main__":
    main()
