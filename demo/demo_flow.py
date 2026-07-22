"""
PHDS 完整流程演示脚本

演示完整的个人健康数据主权协议交互流程：
  1. 患者生成密钥对
  2. 患者加密病历并上传
  3. 数据哈希写入链上存证
  4. 医生请求授权
  5. 患者批准授权（签发 JWT + 会话密钥）
  6. 医生解密查看病历
  7. 授权过期验证
  8. 撤销授权 + 日志审计
  9. 链完整性验证

运行: python demo/demo_flow.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import uuid

# 确保 SDK 在 Python Path 中
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
    print("  PHDS 完整流程演示")
    print("  个人健康数据主权协议")
    print("=" * 60)

    # 临时目录（存储加密文件和日志）
    work_dir = os.path.join(os.path.dirname(__file__), ".phds_demo")
    os.makedirs(work_dir, exist_ok=True)
    log_file = os.path.join(work_dir, "auth.log")
    auth_log = AuthorizationLog(log_file)

    # ============================================================
    # 步骤 1: 患者生成密钥对
    # ============================================================
    print_step(1, "患者（Alice）生成 Ed25519 密钥对")

    patient_pub, patient_priv = generate_keypair()
    patient_hash = public_key_hash(patient_pub)
    patient_pub_pem = export_public_key(patient_pub)
    patient_priv_pem = export_private_key(patient_priv)

    print(f"  患者公钥哈希（匿名标识）: {patient_hash[:16]}...")
    print(f"  公钥 PEM 长度: {len(patient_pub_pem)} 字符")

    # 保存密钥到文件
    with open(os.path.join(work_dir, "patient_pub.pem"), "w") as f:
        f.write(patient_pub_pem)
    with open(os.path.join(work_dir, "patient_priv.pem"), "w") as f:
        f.write(patient_priv_pem)
    print(f"  密钥已保存至: {work_dir}")

    # ============================================================
    # 步骤 2: 患者加密病历并"上传"
    # ============================================================
    print_step(2, "患者加密病历数据")

    # 模拟一份病历明文
    health_record = {
        "patient_name": "Alice",
        "hospital": "XX市人民医院",
        "record_type": "lab_report",
        "date": "2026-07-20",
        "results": {
            "blood_sugar": "5.6 mmol/L",
            "blood_pressure": "120/80 mmHg",
            "heart_rate": "72 bpm",
        },
        "diagnosis": "各项指标正常，建议保持健康生活方式",
    }
    plaintext = json.dumps(health_record, ensure_ascii=False).encode("utf-8")
    print(f"  原始病历: {json.dumps(health_record, ensure_ascii=False, indent=2)[:200]}...")

    # 使用 AES-256-GCM 加密
    aes_key = generate_aes_key()
    encrypted_data = aes_encrypt(aes_key, plaintext)
    encrypted_b64 = base64.b64encode(encrypted_data).decode()
    print(f"  加密完成，密文长度: {len(encrypted_data)} 字节")

    # 创建 BioRecord
    metadata = RecordMetadata(
        hospital_id="hospital_001",
        record_type="lab_report",
        description="Alice 的化验报告",
    )
    record = BioRecord.create(
        patient_pubkey_hash=patient_hash,
        encrypted_data_url=f"phds://{patient_hash}/records/{uuid.uuid4().hex[:8]}",
        encrypted_data=encrypted_data,
        metadata=metadata,
    )
    print(f"  BioRecord 已创建")
    print(f"    record_id: {record.record_id}")
    print(f"    data_hash: {record.data_hash[:16]}...")

    # 用 ECIES 加密 AES 密钥（用患者自己的公钥，模拟发送给存储节点）
    patient_priv_bytes = patient_priv.private_bytes_raw()
    patient_pub_bytes = patient_pub.public_bytes_raw()

    # 在实际场景中，AES 密钥由患者自己保管或用 ECIES 加密后存储
    # 这里演示：将 AES 密钥 base64 编码，供后续解密使用
    aes_key_b64 = base64.b64encode(aes_key).decode()
    print(f"  AES 密钥（base64）: {aes_key_b64[:20]}...")

    # ============================================================
    # 步骤 3: 将数据哈希写入链上存证
    # ============================================================
    print_step(3, "将 BioRecord 的 data_hash 写入链上存证")

    chain = Chain(difficulty=3)
    block = chain.append(record.data_hash)
    print(f"  存证数据哈希: {record.data_hash[:16]}...")
    print(f"  区块高度:     {block.index}")
    print(f"  区块哈希:     {block.hash[:16]}...")
    print(f"  前驱哈希:     {block.prev_hash[:16]}...")
    print(f"  PoW nonce:    {block.nonce}")
    print(f"  链长度:       {len(chain)} 个区块")

    # ============================================================
    # 步骤 4: 医生请求授权
    # ============================================================
    print_step(4, "医生（Bob）发起授权请求")

    # 医生生成自己的密钥对
    doctor_pub, doctor_priv = generate_keypair()
    doctor_hash = public_key_hash(doctor_pub)
    doctor_pub_pem = export_public_key(doctor_pub)
    doctor_priv_pem = export_private_key(doctor_priv)

    # 创建授权请求事件
    auth_event = AuthorizationEvent(
        patient_pubkey_hash=patient_hash,
        requester_id=doctor_hash,
        scope="read",
    )
    print(f"  请求 ID: {auth_event.request_id}")
    print(f"  请求方: 医生 Bob（{doctor_hash[:16]}...）")
    print(f"  患者:   Alice（{patient_hash[:16]}...）")
    print(f"  权限:   {auth_event.scope}")
    print(f"  状态:   {auth_event.status}")

    auth_log.append(AuthorizationLogEntry(
        action="request",
        requester_id=doctor_hash,
        patient_hash=patient_hash,
        scope="read",
    ))

    # ============================================================
    # 步骤 5: 患者批准授权
    # ============================================================
    print_step(5, "患者批准授权（签发 JWT + 生成会话密钥）")

    # 生成会话密钥
    session_key = generate_session_key()
    session_key_b64 = base64.b64encode(session_key).decode()

    # 签发授权 JWT
    jwt_token = create_authorization_jwt(
        patient_private_key=patient_priv,
        patient_public_key=patient_pub,
        requester_id=doctor_hash,
        scope="read",
        expire_seconds=DEFAULT_EXPIRE_SECONDS,
    )

    # 验证 JWT
    payload = verify_authorization_jwt(jwt_token, patient_pub)
    assert payload is not None, "JWT 验证失败！"

    # 更新授权事件
    auth_event.approve(session_key_b64, float(payload["exp"]), payload["jti"])
    print(f"  授权已批准")
    print(f"  JWT ID (jti): {payload['jti'][:16]}...")
    print(f"  过期时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload['exp']))}")
    print(f"  会话密钥: {session_key_b64[:20]}...")

    auth_log.append(AuthorizationLogEntry(
        action="approve",
        requester_id=doctor_hash,
        patient_hash=patient_hash,
        jti=payload["jti"],
        scope="read",
        expire_at=float(payload["exp"]),
    ))

    # ============================================================
    # 步骤 6: 医生解密查看病历
    # ============================================================
    print_step(6, "医生使用会话密钥解密并查看病历")

    # 医生端：用 AES 密钥解密病历（实际场景中该密钥通过 ECIES 安全传递）
    try:
        decrypted_data = aes_decrypt(aes_key, encrypted_data)
        record_data = json.loads(decrypted_data.decode("utf-8"))
        print(f"  解密成功！病历内容:")
        print(f"  {json.dumps(record_data, ensure_ascii=False, indent=4)}")
    except Exception as e:
        print(f"  解密失败: {e}")

    # 验证数据完整性
    print(f"\n  数据完整性验证: ", end="")
    if record.verify_integrity(encrypted_data):
        print("通过")
    else:
        print("失败 — 数据可能被篡改！")

    # ============================================================
    # 步骤 7: 授权过期验证
    # ============================================================
    print_step(7, "验证：使用短效授权（5秒后过期）")

    # 创建一个 5 秒过期的 JWT
    short_jwt = create_authorization_jwt(
        patient_private_key=patient_priv,
        patient_public_key=patient_pub,
        requester_id=doctor_hash,
        scope="read",
        expire_seconds=5,
    )

    # 立即验证 → 通过
    payload1 = verify_authorization_jwt(short_jwt, patient_pub)
    print(f"  立即验证: {'通过' if payload1 else '失败'}")

    # 等待 6 秒后验证 → 过期
    print(f"  等待 6 秒...")
    time.sleep(6)
    payload2 = verify_authorization_jwt(short_jwt, patient_pub)
    print(f"  6 秒后验证: {'通过' if payload2 else '失败（JWT 已过期）'}")

    # ============================================================
    # 步骤 8: 撤销授权
    # ============================================================
    print_step(8, "撤销授权 + 日志审计")

    from sdk.core.auth import revoke_authorization

    # 撤销之前的授权
    result = revoke_authorization(jwt_token, patient_pub)
    print(f"  撤销结果: {'成功' if result else '失败'}")

    # 验证撤销后的 JWT
    revocation_set = {payload["jti"]}
    payload3 = verify_authorization_jwt(jwt_token, patient_pub, revocation_set)
    print(f"  撤销后验证: {'通过' if payload3 else '失败（已被撤销）'}")

    auth_log.append(AuthorizationLogEntry(
        action="revoke",
        requester_id=doctor_hash,
        patient_hash=patient_hash,
        jti=payload["jti"],
        scope="read",
    ))

    # ============================================================
    # 日志审计
    # ============================================================
    print(f"\n{SUB}")
    print("  授权日志审计")
    print(SUB)

    entries = auth_log.read_all()
    print(f"  共 {len(entries)} 条日志记录:\n")
    for i, entry in enumerate(entries, 1):
        ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
        print(f"  [{i}] {ts} | {entry.action:8s} | "
              f"requester={entry.requester_id[:12]}... | "
              f"jti={entry.jti[:12] if entry.jti else 'N/A':>12}")

    # ============================================================
    # 步骤 9: 验证链完整性，证明不可篡改
    # ============================================================
    print_step(9, "验证链完整性 — 证明不可篡改")

    print(f"  链长度: {len(chain)} 个区块")

    # 验证完整链
    is_valid = chain.verify()
    print(f"  链完整性验证: {'通过' if is_valid else '失败'}")

    # 检索存证记录
    found = chain.find_by_hash(record.data_hash)
    print(f"  存证记录查询: {'已找到' if found else '未找到'}")
    if found:
        print(f"    区块高度: {found.index}")
        print(f"    存证时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(found.timestamp))}")
        print(f"    区块哈希: {found.hash[:16]}...")

    # 演示篡改检测
    print(f"\n  模拟篡改检测:")
    original_data_hash = chain.chain[1].data_hash
    chain.chain[1].data_hash = "tampered_hash"
    tampered_valid = chain.verify()
    print(f"    篡改数据哈希后链完整性: {'通过（危险）' if tampered_valid else '失败（已检测到篡改）'}")
    # 恢复
    chain.chain[1].data_hash = original_data_hash

    # ============================================================
    # 总结
    # ============================================================
    print(f"\n{SEP}")
    print("  流程演示完成！")
    print(SEP)
    print(f"""
  PHDS 协议核心流程总结:

  1. 患者拥有密钥对 → 公钥哈希作为匿名标识
  2. 病历数据由患者端 AES-256-GCM 加密后上传
  3. 数据哈希写入链上存证，不可篡改
  4. 医生发起授权请求 → 患者审批
  5. 患者用私钥签发 JWT + 生成一次性会话密钥
  6. 医生凭会话密钥在有效期内解密病历
  7. 授权可随时撤销，JWT 加入撤销列表
  8. 所有授权事件记录在不可篡改的日志中
  9. 链完整性验证 → 证明存证不可篡改

  产出文件:
    - 密钥: {work_dir}/patient_pub.pem, patient_priv.pem
    - 日志: {log_file}
""")


if __name__ == "__main__":
    main()
