"""
PHDS 简化患者模式完整流程演示

使用手机号 + PIN 替代助记词管理密钥，9 步完整流程：
  1. 患者用手机号+PIN 派生密钥对
  2. 患者加密病历
  3. 链上存证
  4. 医生请求授权
  5. 患者批准授权（签发 JWT）
  6. 医生解密查看病历
  7. 授权过期验证
  8. 撤销授权 + 日志审计
  9. 换设备恢复验证（手机号+PIN → 相同密钥）

运行: python demo/demo_lite_flow.py
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
    export_private_key,
    public_key_hash,
    load_public_key,
    load_private_key,
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
    AuthorizationLog,
    AuthorizationLogEntry,
    DEFAULT_EXPIRE_SECONDS,
)
from sdk.core.lite_keys import (
    derive_keypair,
    verify_pin,
    get_public_key_hash,
)
from sdk.records.bio_record import BioRecord, RecordMetadata
from sdk.records.authorization import AuthorizationEvent, AuthorizationStatus
from sdk.core.chain import Chain


SEP = "=" * 60
SUB = "-" * 40


def print_step(n: int, title: str) -> None:
    """打印步骤标题。"""
    print(f"\n{SEP}")
    print(f"  步骤 {n}: {title}")
    print(SEP)


def main() -> None:
    print("\n" + "=" * 60)
    print("  PHDS 简化患者模式 — 完整流程演示")
    print("  手机号 + PIN → 自动派生密钥（无密钥文件）")
    print("=" * 60)

    # 临时目录
    work_dir = os.path.join(os.path.dirname(__file__), ".phds_lite_demo")
    os.makedirs(work_dir, exist_ok=True)
    log_file = os.path.join(work_dir, "auth.log")
    auth_log = AuthorizationLog(log_file)

    # ── 用户凭据 ────────────────────────────────────────
    patient_phone = "13800138000"
    patient_pin = "123456"

    # ============================================================
    # 步骤 1: 患者用手机号+PIN 派生密钥对
    # ============================================================
    print_step(1, "患者（Alice）用手机号+PIN 派生密钥对")

    patient_pub, patient_priv = derive_keypair(patient_phone, patient_pin)
    patient_hash = public_key_hash(patient_pub)
    patient_pub_pem = export_public_key(patient_pub)
    patient_priv_pem = export_private_key(patient_priv)

    print(f"  手机号: {patient_phone}")
    print(f"  PIN:     {patient_pin}")
    print(f"  派生公钥哈希（匿名标识）: {patient_hash[:16]}...")
    print(f"  公钥 PEM 长度: {len(patient_pub_pem)} 字符")
    print(f"  注意：私钥不落盘，内存中派生后使用，退出即消失")

    # 保存公钥 PEM 到文件（仅用于后续步骤演示，实际应用中可存服务器）
    with open(os.path.join(work_dir, "patient_pub.pem"), "w") as f:
        f.write(patient_pub_pem)
    print(f"  公钥已保存至: {work_dir}（私钥不保存）")

    # ============================================================
    # 步骤 2: 患者加密病历
    # ============================================================
    print_step(2, "患者加密病历数据")

    health_record = {
        "patient_name": "Alice",
        "phone": patient_phone,
        "hospital": "XX市人民医院",
        "record_type": "lab_report",
        "date": "2026-07-22",
        "results": {
            "blood_sugar": "5.6 mmol/L",
            "blood_pressure": "120/80 mmHg",
            "heart_rate": "72 bpm",
        },
        "diagnosis": "各项指标正常",
    }
    plaintext = json.dumps(health_record, ensure_ascii=False).encode("utf-8")
    print(f"  原始病历: {json.dumps(health_record, ensure_ascii=False, indent=2)[:200]}...")

    aes_key = generate_aes_key()
    encrypted_data = aes_encrypt(aes_key, plaintext)
    encrypted_b64 = base64.b64encode(encrypted_data).decode()
    print(f"  加密完成，密文长度: {len(encrypted_data)} 字节")

    metadata = RecordMetadata(
        hospital_id="hospital_001",
        record_type="lab_report",
        description="Alice 化验报告（简化模式）",
    )
    record = BioRecord.create(
        patient_pubkey_hash=patient_hash,
        encrypted_data_url=f"phds://{patient_hash}/records/{uuid.uuid4().hex[:8]}",
        encrypted_data=encrypted_data,
        metadata=metadata,
    )
    print(f"  BioRecord 已创建: {record.record_id}")

    # ============================================================
    # 步骤 3: 链上存证
    # ============================================================
    print_step(3, "将 BioRecord.data_hash 写入链上存证")

    chain = Chain(difficulty=3)
    block = chain.append(record.data_hash)
    print(f"  存证哈希: {record.data_hash[:16]}...")
    print(f"  区块高度: {block.index}")
    print(f"  链长度:   {len(chain)} 个区块")
    print(f"  链完整性: {'有效' if chain.verify() else '无效'}")

    # ============================================================
    # 步骤 4: 医生请求授权
    # ============================================================
    print_step(4, "医生（Bob）发起授权请求")

    doctor_pub, doctor_priv = generate_keypair()
    doctor_hash = public_key_hash(doctor_pub)

    auth_event = AuthorizationEvent(
        patient_pubkey_hash=patient_hash,
        requester_id=doctor_hash,
        scope="read",
    )
    print(f"  请求 ID: {auth_event.request_id}")
    print(f"  请求方:  医生 Bob（{doctor_hash[:16]}...）")
    print(f"  状态:    {auth_event.status}")

    auth_log.append(AuthorizationLogEntry(
        action="request",
        requester_id=doctor_hash,
        patient_hash=patient_hash,
        scope="read",
    ))

    # ============================================================
    # 步骤 5: 患者批准授权
    # ============================================================
    print_step(5, "患者批准授权（签发 JWT）")

    session_key = generate_session_key()
    session_key_b64 = base64.b64encode(session_key).decode()

    jwt_token = create_authorization_jwt(
        patient_private_key=patient_priv,
        patient_public_key=patient_pub,
        requester_id=doctor_hash,
        scope="read",
        expire_seconds=DEFAULT_EXPIRE_SECONDS,
    )

    payload = verify_authorization_jwt(jwt_token, patient_pub)
    assert payload is not None, "JWT 验证失败！"
    auth_event.approve(session_key_b64, float(payload["exp"]), payload["jti"])

    print(f"  授权已批准")
    print(f"  JWT jti:    {payload['jti'][:16]}...")
    print(f"  过期时间:   {time.strftime('%H:%M:%S', time.localtime(payload['exp']))}")

    auth_log.append(AuthorizationLogEntry(
        action="approve",
        requester_id=doctor_hash,
        patient_hash=patient_hash,
        jti=payload["jti"],
        scope="read",
        expire_at=float(payload["exp"]),
    ))

    # ============================================================
    # 步骤 6: 医生解密查看
    # ============================================================
    print_step(6, "医生解密查看病历")

    try:
        decrypted_data = aes_decrypt(aes_key, encrypted_data)
        record_data = json.loads(decrypted_data.decode("utf-8"))
        print(f"  解密成功！病历内容:")
        print(f"  {json.dumps(record_data, ensure_ascii=False, indent=4)}")
    except Exception as e:
        print(f"  解密失败: {e}")

    print(f"  数据完整性: {'通过' if record.verify_integrity(encrypted_data) else '失败'}")

    # ============================================================
    # 步骤 7: 授权过期验证
    # ============================================================
    print_step(7, "短效授权过期验证（5 秒）")

    short_jwt = create_authorization_jwt(
        patient_private_key=patient_priv,
        patient_public_key=patient_pub,
        requester_id=doctor_hash,
        scope="read",
        expire_seconds=5,
    )
    p1 = verify_authorization_jwt(short_jwt, patient_pub)
    print(f"  立即验证: {'通过' if p1 else '失败'}")
    print(f"  等待 6 秒...")
    time.sleep(6)
    p2 = verify_authorization_jwt(short_jwt, patient_pub)
    print(f"  6 秒后:   {'通过' if p2 else '失败（已过期）'}")

    # ============================================================
    # 步骤 8: 撤销授权 + 日志审计
    # ============================================================
    print_step(8, "撤销授权 + 日志审计")

    from sdk.core.auth import revoke_authorization

    result = revoke_authorization(jwt_token, patient_pub)
    print(f"  撤销结果: {'成功' if result else '失败'}")

    revocation_set = {payload["jti"]}
    p3 = verify_authorization_jwt(jwt_token, patient_pub, revocation_set)
    print(f"  撤销后验证: {'通过' if p3 else '失败（已撤销）'}")

    auth_log.append(AuthorizationLogEntry(
        action="revoke",
        requester_id=doctor_hash,
        patient_hash=patient_hash,
        jti=payload["jti"],
        scope="read",
    ))

    # 日志审计
    print(f"\n{SUB}")
    print("  授权日志审计")
    print(SUB)
    entries = auth_log.read_all()
    print(f"  共 {len(entries)} 条记录:")
    for i, entry in enumerate(entries, 1):
        ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
        print(f"  [{i}] {ts} | {entry.action:8s} | "
              f"requester={entry.requester_id[:12]}... | "
              f"jti={entry.jti[:12] if entry.jti else 'N/A'}")

    # ============================================================
    # 步骤 9: 换设备恢复验证
    # ============================================================
    print_step(9, "换设备恢复验证 — 同一手机号+PIN → 相同密钥")

    # 模拟"新设备"重新派生
    new_pub, new_priv = derive_keypair(patient_phone, patient_pin)
    new_hash = public_key_hash(new_pub)

    print(f"  原始公钥哈希: {patient_hash[:16]}...")
    print(f"  恢复公钥哈希: {new_hash[:16]}...")
    print(f"  密钥一致:     {'是' if patient_hash == new_hash else '否'}")

    # PIN 验证
    assert verify_pin(patient_phone, patient_pin, patient_pub), "PIN 验证应通过"
    print(f"  PIN 验证:     通过")

    # 错误 PIN 验证
    assert not verify_pin(patient_phone, "000000", patient_pub), "错误 PIN 应失败"
    print(f"  错误 PIN:     拒绝（预期行为）")

    # 换设备后用恢复的密钥解密
    recovered_priv_bytes = new_priv.private_bytes_raw()
    patient_priv_bytes = patient_priv.private_bytes_raw()
    assert recovered_priv_bytes == patient_priv_bytes
    print(f"  私钥原始字节: 一致（换设备可恢复）")

    # ============================================================
    # 总结
    # ============================================================
    print(f"\n{SEP}")
    print("  简化患者模式流程演示完成！")
    print(SEP)
    print(f"""
  PHDS 简化模式 vs 标准模式:

  ┌──────────────┬─────────────────────┬─────────────────────┐
  │ 维度         │ 标准模式            │ 简化模式            │
  ├──────────────┼─────────────────────┼─────────────────────┤
  │ 密钥来源     │ 随机生成 + BIP39    │ PBKDF2 确定性派生   │
  │ 用户记忆     │ 24 个助记词         │ 手机号 + 6 位 PIN   │
  │ 私钥存储     │ 本地 PEM 文件      │ 不存储，每次派生     │
  │ 换设备恢复   │ 输入助记词          │ 输入手机号 + PIN     │
  │ 安全性       │ 高（256 位熵）      │ 中（依赖 PIN 强度）  │
  │ 适用场景     │ 高级用户/机构       │ 普通患者/移动端     │
  └──────────────┴─────────────────────┴─────────────────────┘

  产出文件:
    - 公钥: {work_dir}/patient_pub.pem
    - 日志: {log_file}
""")


if __name__ == "__main__":
    main()
