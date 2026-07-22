"""
PHDS 链上存证模块单元测试

覆盖:
  - Chain: 追加区块、完整性验证、防篡改验证
  - 篡改检测（修改数据/修改 prev_hash）
  - 哈希查询
  - 多区块一致性
  - 序列化/反序列化

运行: python -m pytest tests/test_chain.py -v
      或: python tests/test_chain.py
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sdk.core.chain import Chain, Block


class TestChain(unittest.TestCase):
    """链上存证测试"""

    def setUp(self) -> None:
        """每个测试前创建新链。"""
        self.chain = Chain(difficulty=2)  # 降低难度以加速测试

    # ── 基础测试 ──────────────────────────────────────────

    def test_genesis_block(self) -> None:
        """测试创世区块自动生成"""
        self.assertEqual(len(self.chain.chain), 1)
        genesis = self.chain.chain[0]
        self.assertEqual(genesis.index, 0)
        self.assertEqual(genesis.data_hash, "genesis")
        self.assertEqual(genesis.prev_hash, "0" * 64)
        self.assertNotEqual(genesis.hash, "")

    def test_append_block(self) -> None:
        """测试追加区块"""
        block = self.chain.append("data_hash_001")
        self.assertEqual(len(self.chain), 2)
        self.assertEqual(block.index, 1)
        self.assertEqual(block.data_hash, "data_hash_001")
        self.assertTrue(block.hash.startswith("0" * self.chain.difficulty))

    def test_chain_verify_valid(self) -> None:
        """测试完整链的完整性验证"""
        for i in range(5):
            self.chain.append(f"data_hash_{i:03d}")
        self.assertTrue(self.chain.verify())

    # ── 防篡改测试 ────────────────────────────────────────

    def test_tampered_data_detected(self) -> None:
        """测试篡改区块数据后被检测"""
        self.chain.append("original_data")
        self.chain.append("another_data")

        # 修改第一个数据区块的数据哈希
        self.chain.chain[1].data_hash = "tampered_data"

        self.assertFalse(self.chain.verify())

    def test_tampered_prev_hash_detected(self) -> None:
        """测试篡改 prev_hash 后被检测"""
        self.chain.append("data_1")
        self.chain.append("data_2")

        # 修改第二个区块的 prev_hash
        self.chain.chain[2].prev_hash = "0" * 64

        self.assertFalse(self.chain.verify())

    def test_tampered_hash_detected(self) -> None:
        """测试直接修改区块哈希后被检测"""
        self.chain.append("data_1")

        # 直接修改哈希值
        old_hash = self.chain.chain[1].hash
        self.chain.chain[1].hash = "a" * 64

        self.assertFalse(self.chain.verify())

    # ── 查询测试 ──────────────────────────────────────────

    def test_find_by_hash_exists(self) -> None:
        """测试按数据哈希查询（存在）"""
        self.chain.append("hash_abc")
        self.chain.append("hash_def")

        block = self.chain.find_by_hash("hash_abc")
        self.assertIsNotNone(block)
        self.assertEqual(block.data_hash, "hash_abc")

    def test_find_by_hash_not_exists(self) -> None:
        """测试按数据哈希查询（不存在）"""
        self.chain.append("hash_abc")

        block = self.chain.find_by_hash("nonexistent")
        self.assertIsNone(block)

    def test_find_by_data_hash_multiple(self) -> None:
        """测试同一数据哈希多次存证的查询"""
        self.chain.append("same_hash")
        self.chain.append("other_hash")
        self.chain.append("same_hash")  # 再次存证

        results = self.chain.find_by_data_hash("same_hash")
        self.assertEqual(len(results), 2)

    # ── 多区块一致性测试 ──────────────────────────────────

    def test_multi_block_consistency(self) -> None:
        """测试多个区块的链一致性"""
        hashes = [f"data_{i}" for i in range(10)]
        blocks = []

        for h in hashes:
            block = self.chain.append(h)
            blocks.append(block)

        self.assertEqual(len(self.chain), 11)  # 10 数据块 + 1 genesis
        self.assertTrue(self.chain.verify())

        # 验证每个区块的 prev_hash 链接正确
        for i in range(1, len(self.chain.chain)):
            current = self.chain.chain[i]
            previous = self.chain.chain[i - 1]
            self.assertEqual(current.prev_hash, previous.hash)

    # ── 序列化测试 ────────────────────────────────────────

    def test_serialize_roundtrip(self) -> None:
        """测试链的 JSON 序列化往返"""
        self.chain.append("data_1")
        self.chain.append("data_2")

        json_str = self.chain.to_json()
        chain2 = Chain.from_dict(self.chain.to_dict(), difficulty=2)

        self.assertEqual(len(chain2), len(self.chain))
        self.assertTrue(chain2.verify())

        # 验证区块数据一致
        for b1, b2 in zip(self.chain.chain, chain2.chain):
            self.assertEqual(b1.hash, b2.hash)
            self.assertEqual(b1.data_hash, b2.data_hash)
            self.assertEqual(b1.index, b2.index)

    def test_last_block_property(self) -> None:
        """测试 last_block 属性"""
        self.chain.append("first")
        self.assertEqual(self.chain.last_block.data_hash, "first")

        self.chain.append("second")
        self.assertEqual(self.chain.last_block.data_hash, "second")

    def test_chain_length(self) -> None:
        """测试 __len__"""
        self.assertEqual(len(self.chain), 1)
        self.chain.append("a")
        self.assertEqual(len(self.chain), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
