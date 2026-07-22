"""
PHDS JWT 撤销列表 — 共享 SQLite 持久化存储

与 DatabaseManager 共享同一个 SQLite 数据库，在同一个文件内新建 revocations 表。

表结构（revoked_tokens）:
  - id:         自增主键
  - jti:        被撤销的 JWT ID（唯一，主索引）
  - revoked_at: 撤销时间戳
  - reason:     撤销原因（可选）

用法::

    from sqlalchemy import create_engine
    from sdk.storage.revocation_store import RevocationStore

    engine = create_engine("sqlite:///data/phds.db")
    store = RevocationStore(engine)
    store.create_tables()
    store.revoke("jti_abc123", reason="用户主动撤销")
    assert store.is_revoked("jti_abc123") is True
"""
from __future__ import annotations

import time
from typing import List, Optional, Set

from sqlalchemy import Column, Float, Integer, String, Text, Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


# ============================================================
# SQLAlchemy 基类 — 独立基类，不干扰 database.py 的 Base
# ============================================================

class _RevocationBase(DeclarativeBase):
    """撤销存储专用声明式基类。"""
    pass


# ============================================================
# 数据模型 — revoked_tokens 表
# ============================================================

class RevokedToken(_RevocationBase):
    """已撤销 JWT 记录。

    Attributes:
        id:         自增主键
        jti:        JWT ID（唯一，主索引）
        revoked_at: 撤销时间戳
        reason:     撤销原因
    """
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    revoked_at = Column(Float, default=time.time)
    reason = Column(Text, default="")


# ============================================================
# RevocationStore — 接收共享 Engine
# ============================================================

class RevocationStore:
    """JWT 撤销列表的 SQLite 存储。

    与 DatabaseManager 共享同一个 SQLAlchemy Engine，所有表写入同一个数据库文件。

    特性:
      - 通过构造函数接收已有的 Engine，不自行创建连接
      - create_tables() 仅创建 revoked_tokens 表（幂等）
      - 支持批量撤销、查询、清理

    Attributes:
        engine:  SQLAlchemy Engine（外部传入）
        Session: sessionmaker 工厂
    """

    def __init__(self, engine: Engine):
        """初始化撤销存储。

        Args:
            engine: 已存在的 SQLAlchemy Engine（与 DatabaseManager 共享）
        """
        self.engine = engine
        self.Session = sessionmaker(bind=self.engine)

    def create_tables(self) -> None:
        """创建 revoked_tokens 表（如果不存在）。"""
        _RevocationBase.metadata.create_all(self.engine)

    def revoke(self, jti: str, reason: str = "") -> bool:
        """撤销一个 JWT（将其 jti 加入撤销列表）。

        Args:
            jti:    要撤销的 JWT ID
            reason: 可选的撤销原因

        Returns:
            True 表示撤销成功，False 表示该 jti 已存在
        """
        with self.Session() as session:
            existing = (
                session.query(RevokedToken).filter(RevokedToken.jti == jti).first()
            )
            if existing is not None:
                return False
            row = RevokedToken(jti=jti, revoked_at=time.time(), reason=reason)
            session.add(row)
            session.commit()
            return True

    def is_revoked(self, jti: str) -> bool:
        """检查 JWT 是否已被撤销。

        Args:
            jti: JWT ID

        Returns:
            True 表示已撤销
        """
        with self.Session() as session:
            return (
                session.query(RevokedToken).filter(RevokedToken.jti == jti).first()
                is not None
            )

    def get_all_revoked(self) -> Set[str]:
        """获取所有已撤销的 jti 集合。

        Returns:
            jti 字符串集合
        """
        with self.Session() as session:
            rows = session.query(RevokedToken).all()
            return {row.jti for row in rows}

    def batch_is_revoked(self, jtis: List[str]) -> Set[str]:
        """批量检查哪些 jti 已被撤销。

        Args:
            jtis: JWT ID 列表

        Returns:
            已撤销的 jti 集合
        """
        with self.Session() as session:
            rows = (
                session.query(RevokedToken)
                .filter(RevokedToken.jti.in_(jtis))
                .all()
            )
            return {row.jti for row in rows}

    def count(self) -> int:
        """查询已撤销的 JWT 数量。

        Returns:
            计数
        """
        with self.Session() as session:
            return session.query(RevokedToken).count()

    def clear_all(self) -> int:
        """清空全部撤销记录（慎用）。

        Returns:
            删除的记录数
        """
        with self.Session() as session:
            count = session.query(RevokedToken).count()
            session.query(RevokedToken).delete()
            session.commit()
            return count

    def expire_entries(self) -> int:
        """清理过期的撤销记录。

        移除所有 revoked_at 早于当前时间的记录。
        注意：撤销记录本身无过期概念，此方法为接口兼容性预留，
        实际行为等同于清空全部（因为撤销是永久性的）。

        Returns:
            删除的记录数
        """
        return self.clear_all()

    def remove_expired(self, before_timestamp: float) -> int:
        """移除指定时间之前的撤销记录（用于定期清理）。

        Args:
            before_timestamp: 此时间之前的记录将被删除

        Returns:
            删除的记录数
        """
        with self.Session() as session:
            count = (
                session.query(RevokedToken)
                .filter(RevokedToken.revoked_at < before_timestamp)
                .delete()
            )
            session.commit()
            return count
