"""
PHDS 链上存证模块

提供简化版 Merkle Tree 链，模拟不可篡改的存证层：
  - 每条记录存：数据哈希 + 上一条区块哈希 + 时间戳 + nonce（轻量 PoW）
  - 支持追加记录、验证链完整性、按哈希查询
  - 支持可选 SQLite 持久化（db_path 参数），默认内存模式兼容现有 demo

为 PHDS 提供防篡改的存证能力，确保 BioRecord 的数据哈希一经上链便不可抵赖。

用法::

    from sdk.core.chain import Chain

    # 内存模式（默认，兼容现有 demo）
    chain = Chain(difficulty=3)
    block = chain.append("abc123_data_hash")
    assert chain.verify() is True

    # 持久化模式
    chain = Chain(difficulty=3, db_path="data/chain.db")
    block = chain.append("abc123_data_hash")
    # 重启后链数据自动恢复
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ── 常量 ────────────────────────────────────────────────────
DEFAULT_DIFFICULTY = 3  # 轻量 PoW 难度（前导零个数）


# ============================================================
# Block 数据结构
# ============================================================

@dataclass
class Block:
    """链上区块。

    Attributes:
        index:       区块序号（从 0 开始）
        timestamp:   Unix 时间戳
        data_hash:   存证的数据哈希
        prev_hash:   前一个区块的哈希
        nonce:       PoW 随机数
        hash:        本区块哈希（由自身数据计算）
    """
    index: int
    timestamp: float
    data_hash: str
    prev_hash: str
    nonce: int
    hash: str = ""

    def compute_hash(self) -> str:
        """计算本区块的 SHA-256 哈希。"""
        payload = (
            f"{self.index}"
            f"{self.timestamp}"
            f"{self.data_hash}"
            f"{self.prev_hash}"
            f"{self.nonce}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ============================================================
# Chain 链
# ============================================================

class Chain:
    """简化版区块链接口。

    模拟不可篡改的存证层：
    - genesis 区块自动生成
    - 每条追加记录需完成轻量 PoW
    - 提供链完整性验证与哈希查询
    - 可选 SQLite 持久化（db_path 参数），默认内存模式

    Attributes:
        difficulty: PoW 难度（前导零个数，默认 3）
        chain:      区块列表（genesis 在索引 0）
        db_path:    SQLite 数据库路径（None 表示纯内存模式）
    """

    def __init__(
        self,
        difficulty: int = DEFAULT_DIFFICULTY,
        db_path: Optional[str] = None,
    ):
        """初始化链。

        Args:
            difficulty: PoW 难度（前导零个数）
            db_path:    可选 SQLite 持久化路径。
                        传入时自动建表并从数据库恢复链数据；
                        不传入时保持纯内存模式。
        """
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

        if db_path is not None:
            # 确保父目录存在
            parent_dir = os.path.dirname(db_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            self._conn = sqlite3.connect(db_path)
            self._conn.row_factory = sqlite3.Row
            self._init_db()
            self._load_from_db()

        # 如果链为空（无持久化或数据库无记录），创建创世区块
        if not self.chain:
            genesis = Block(
                index=0,
                timestamp=time.time(),
                data_hash="genesis",
                prev_hash="0" * 64,
                nonce=0,
            )
            genesis.hash = genesis.compute_hash()
            self.chain.append(genesis)
            if self._conn is not None:
                self._save_block(genesis)

    # ── 持久化辅助 ──────────────────────────────────────────

    def _init_db(self) -> None:
        """创建 chain_blocks 表（如果不存在）。"""
        if self._conn is None:
            return
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS chain_blocks (
                block_index INTEGER PRIMARY KEY,
                timestamp  REAL NOT NULL,
                data_hash  TEXT NOT NULL,
                prev_hash  TEXT NOT NULL,
                nonce      INTEGER NOT NULL,
                block_hash TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def _save_block(self, block: Block) -> None:
        """将单个区块写入 SQLite。"""
        if self._conn is None:
            return
        self._conn.execute(
            """
            INSERT OR REPLACE INTO chain_blocks
                (block_index, timestamp, data_hash, prev_hash, nonce, block_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (block.index, block.timestamp, block.data_hash,
             block.prev_hash, block.nonce, block.hash),
        )
        self._conn.commit()

    def _load_from_db(self) -> None:
        """从 SQLite 加载全部区块到内存。"""
        if self._conn is None:
            return
        rows = self._conn.execute(
            "SELECT * FROM chain_blocks ORDER BY block_index"
        ).fetchall()
        self.chain = []
        for row in rows:
            block = Block(
                index=row["block_index"],
                timestamp=row["timestamp"],
                data_hash=row["data_hash"],
                prev_hash=row["prev_hash"],
                nonce=row["nonce"],
                hash=row["block_hash"],
            )
            self.chain.append(block)

    # ── 公共接口 ────────────────────────────────────────────

    @property
    def last_block(self) -> Block:
        """返回链上最后一个区块。"""
        return self.chain[-1]

    def _mine(self, block: Block) -> Block:
        """执行轻量 PoW：找到满足难度条件的 nonce。

        Args:
            block: 待挖矿的区块（nonce=0）

        Returns:
            挖矿完成后的区块（已填入哈希）
        """
        prefix = "0" * self.difficulty
        while True:
            block.hash = block.compute_hash()
            if block.hash.startswith(prefix):
                return block
            block.nonce += 1

    def append(self, data_hash: str) -> Block:
        """追加一条存证记录。

        Args:
            data_hash: 要存证的数据哈希（如 BioRecord.data_hash）

        Returns:
            新创建的区块
        """
        prev = self.last_block
        block = Block(
            index=prev.index + 1,
            timestamp=time.time(),
            data_hash=data_hash,
            prev_hash=prev.hash,
            nonce=0,
        )
        self._mine(block)
        self.chain.append(block)

        # 持久化到 SQLite（如启用）
        if self._conn is not None:
            self._save_block(block)

        return block

    def verify(self) -> bool:
        """验证整条链的完整性。

        检测以下篡改：
        - 区块哈希是否与内容一致
        - prev_hash 是否指向前一个区块的真实哈希
        - PoW 难度是否满足

        Returns:
            链完整返回 True，否则返回 False
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # 检查哈希是否与内容一致
            if current.hash != current.compute_hash():
                return False

            # 检查 prev_hash 链接
            if current.prev_hash != previous.hash:
                return False

            # 检查 PoW 难度
            prefix = "0" * self.difficulty
            if not current.hash.startswith(prefix):
                return False

        return True

    def find_by_hash(self, data_hash: str) -> Optional[Block]:
        """按存证数据哈希查询区块。

        Args:
            data_hash: 数据哈希

        Returns:
            匹配的 Block，未找到返回 None
        """
        for block in self.chain[1:]:  # 跳过 genesis
            if block.data_hash == data_hash:
                return block
        return None

    def find_by_data_hash(self, data_hash: str) -> List[Block]:
        """查询所有匹配数据哈希的区块（支持同一数据多次存证）。

        Args:
            data_hash: 数据哈希

        Returns:
            匹配的 Block 列表
        """
        return [b for b in self.chain[1:] if b.data_hash == data_hash]

    def to_dict(self) -> dict:
        """将整条链导出为字典。"""
        return {
            "difficulty": self.difficulty,
            "length": len(self.chain),
            "chain": [asdict(b) for b in self.chain],
        }

    def to_json(self) -> str:
        """将整条链导出为 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: dict, difficulty: int = DEFAULT_DIFFICULTY) -> "Chain":
        """从字典恢复链对象（不重新挖矿，直接信任导入数据）。

        Args:
            data:       链字典（由 to_dict 生成）
            difficulty: 难度（与导入数据一致）

        Returns:
            Chain 对象
        """
        chain = cls(difficulty=difficulty)
        chain.chain = []
        for bd in data["chain"]:
            block = Block(
                index=bd["index"],
                timestamp=bd["timestamp"],
                data_hash=bd["data_hash"],
                prev_hash=bd["prev_hash"],
                nonce=bd["nonce"],
                hash=bd["hash"],
            )
            chain.chain.append(block)
        return chain

    def close(self) -> None:
        """关闭 SQLite 连接（仅持久化模式）。"""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __len__(self) -> int:
        return len(self.chain)

    def __repr__(self) -> str:
        mode = "persistent" if self._db_path else "memory"
        return f"<Chain blocks={len(self.chain)} difficulty={self.difficulty} mode={mode}>"

    def __del__(self) -> None:
        """析构时关闭数据库连接。"""
        self.close()
