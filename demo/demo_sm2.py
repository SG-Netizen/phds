"""
PHDS SM2 国密演示脚本

演示 SM2 密钥生成 → 加密 → 解密 的完整链路。

运行: python demo/demo_sm2.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdk.core.keys import generate_sm2_keypair, sm2_encrypt, sm2_decrypt


SEP = "=" * 60
SUB = "-" * 40


def print_step(n: int, title: str) -> None:
    """打印步骤标题。"""
    print(f"\n{SEP}")
    print(f"  步骤 {n}: {title}")
    print(SEP)


def main() -> None:
    print("\n" + SEP)
    print("  PHDS SM2 国密加密演示")
    print("  个人健康数据主权协议 — 国密兼容")
    print(SEP)

    # ============================================================
    # 步骤 1: 生成 SM2 密钥对
    # ============================================================
    print_step(1, "生成 SM2 密钥对")

    public_key_hex, private_key_hex = generate_sm2_keypair()

    print(f"  公钥 (hex): {public_key_hex[:64]}...")
    print(f"  私钥 (hex): {private_key_hex[:64]}...")
    print(f"  公钥长度:   {len(public_key_hex)} 字符（{len(public_key_hex) // 2} 字节）")
    print(f"  私钥长度:   {len(private_key_hex)} 字符（{len(private_key_hex) // 2} 字节）")

    # ============================================================
    # 步骤 2: 准备待加密数据
    # ============================================================
    print_step(2, "准备待加密的健康数据")

    plaintext = (
        "患者姓名: 张三\n"
        "就诊医院: XX市人民医院\n"
        "病历类型: 化验报告\n"
        "血糖值: 5.6 mmol/L\n"
        "血压: 120/80 mmHg\n"
        "诊断: 各项指标正常"
    )

    print(f"  明文内容:\n{plaintext}")
    plaintext_bytes = plaintext.encode("utf-8")
    print(f"  数据长度: {len(plaintext_bytes)} 字节")

    # ============================================================
    # 步骤 3: SM2 加密
    # ============================================================
    print_step(3, "使用 SM2 公钥加密数据")

    t_start = time.perf_counter()
    ciphertext = sm2_encrypt(public_key_hex, plaintext_bytes)
    t_encrypt = time.perf_counter() - t_start

    print(f"  加密耗时: {t_encrypt:.4f} 秒")
    print(f"  密文长度: {len(ciphertext)} 字节")
    print(f"  密文前 40 字节 (hex): {ciphertext[:40].hex()}...")
    print(f"  密文与明文不同: {'是' if ciphertext != plaintext_bytes else '否'}")

    # ============================================================
    # 步骤 4: SM2 解密
    # ============================================================
    print_step(4, "使用 SM2 私钥解密数据")

    t_start = time.perf_counter()
    decrypted = sm2_decrypt(private_key_hex, ciphertext)
    t_decrypt = time.perf_counter() - t_start

    print(f"  解密耗时: {t_decrypt:.4f} 秒")
    print(f"  解密成功: {'是' if decrypted == plaintext_bytes else '否'}")
    print(f"  解密明文:\n{decrypted.decode('utf-8')}")

    # ============================================================
    # 步骤 5: 加密不可逆验证
    # ============================================================
    print_step(5, "验证：错误密钥无法解密")

    _, wrong_private_key = generate_sm2_keypair()

    try:
        _ = sm2_decrypt(wrong_private_key, ciphertext)
        print("  错误密钥解密意外成功（不应该发生）")
    except Exception as e:
        print(f"  错误密钥解密失败: 符合预期")
        print(f"  错误信息: {type(e).__name__}")

    # ============================================================
    # 总结
    # ============================================================
    print(f"\n{SEP}")
    print("  SM2 国密演示完成！")
    print(SEP)
    print(f"""
  SM2 国密加密流程总结:

  1. 生成 SM2 密钥对（基于 ECC 椭圆曲线）
  2. 使用公钥加密 → 输出 C1C3C2 格式密文
  3. 使用私钥解密 → 恢复原始明文
  4. 错误密钥无法解密，保障数据安全

  SM2 是国密标准椭圆曲线公钥密码算法，
  在 PHDS 中提供与 Ed25519 并行的国密合规选项。
""")


if __name__ == "__main__":
    main()
