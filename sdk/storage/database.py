"""
PHDS SQLite 持久化数据库

使用 SQLAlchemy ORM 定义三张表并提供增删改查接口：
  - bio_records:     病历记录
  - authorizations:  授权事件
  - auth_log:        审计日志

用法::

    from sdk.storage.database import Database, BioRecordRow, AuthorizationRow, AuthLogRow

    db = Database("sqlite:///path/to/phds.db")
    db.create_tables()
    db.add_bio_record(...)
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


# ============================================================
# SQLAlchemy 基类
# ============================================================

class Base(DeclarativeBase):
    """SQLAlchemy 声明式基类。"""
    pass


# ============================================================
# 数据模型 — bio_records 表
# ============================================================

class BioRecordRow(Base):
    """病历记录表。

    字段:
        id:                  自增主键
        record_id:           记录唯一标识（UUID hex）
        patient_pubkey_hash: 患者公钥哈希（匿名标识）
        encrypted_data_url:  加密数据存储 URL
        data_hash:           加密数据的 SHA-256 哈希
        hospital_id:         医院 ID
        record_type:         记录类型
        description:         描述
        metadata_json:       完整元数据 JSON
        created_at:          创建时间戳
    """
    __tablename__ = "bio_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    record_id = Column(String(64), unique=True, nullable=False, index=True)
    patient_pubkey_hash = Column(String(64), nullable=False, index=True)
    encrypted_data_url = Column(Text, nullable=False)
    data_hash = Column(String(64), nullable=False)
    hospital_id = Column(String(128), default="")
    record_type = Column(String(64), default="")
    description = Column(Text, default="")
    metadata_json = Column(Text, default="{}")
    created_at = Column(Float, default=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """转为字典。"""
        return {
            "record_id": self.record_id,
            "patient_pubkey_hash": self.patient_pubkey_hash,
            "encrypted_data_url": self.encrypted_data_url,
            "data_hash": self.data_hash,
            "metadata": json.loads(self.metadata_json) if self.metadata_json else {},
            "created_at": self.created_at,
        }


# ============================================================
# 数据模型 — authorizations 表
# ============================================================

class AuthorizationRow(Base):
    """授权事件表。

    字段:
        id:                  自增主键
        request_id:          请求唯一 ID
        patient_pubkey_hash: 患者公钥哈希
        requester_id:        请求方标识
        session_key:         会话密钥（base64）
        expire_at:           过期时间戳
        status:              状态（pending/approved/revoked/expired/denied）
        scope:               权限范围
        jti:                 JWT ID
        created_at:          创建时间
        updated_at:          更新时间
    """
    __tablename__ = "authorizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), unique=True, nullable=False, index=True)
    patient_pubkey_hash = Column(String(64), nullable=False, index=True)
    requester_id = Column(String(128), nullable=False)
    session_key = Column(Text, default="")
    expire_at = Column(Float, default=0.0)
    status = Column(String(16), default="pending", index=True)
    scope = Column(String(32), default="read")
    jti = Column(String(64), default="", index=True)
    created_at = Column(Float, default=time.time)
    updated_at = Column(Float, default=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """转为字典。"""
        return {
            "request_id": self.request_id,
            "patient_pubkey_hash": self.patient_pubkey_hash,
            "requester_id": self.requester_id,
            "session_key": self.session_key,
            "expire_at": self.expire_at,
            "status": self.status,
            "scope": self.scope,
            "jti": self.jti,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ============================================================
# 数据模型 — auth_log 表
# ============================================================

class AuthLogRow(Base):
    """审计日志表。

    字段:
        id:            自增主键
        event_id:      事件唯一 ID
        timestamp:     事件时间戳
        action:        动作类型（request/approve/revoke/expire）
        requester_id:  请求方标识
        patient_hash:  患者公钥哈希
        jti:           JWT ID
        scope:         权限范围
        expire_at:     过期时间戳
    """
    __tablename__ = "auth_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(Float, default=time.time)
    action = Column(String(16), nullable=False, index=True)
    requester_id = Column(String(128), default="")
    patient_hash = Column(String(64), default="", index=True)
    jti = Column(String(64), default="")
    scope = Column(String(32), default="read")
    expire_at = Column(Float, default=0.0)

    def to_dict(self) -> Dict[str, Any]:
        """转为字典。"""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "requester_id": self.requester_id,
            "patient_hash": self.patient_hash,
            "jti": self.jti,
            "scope": self.scope,
            "expire_at": self.expire_at,
        }


# ============================================================
# Database 管理类
# ============================================================

class DatabaseManager:
    """SQLite 数据库管理类。

    封装 SQLAlchemy 引擎、会话工厂和针对三张表的增删改查方法。

    Attributes:
        engine:     SQLAlchemy Engine
        Session:    sessionmaker 工厂
        db_url:     数据库连接 URL
    """

    def __init__(self, db_path: str = "data/phds.db"):
        """初始化数据库连接。

        Args:
            db_path: SQLite 数据库文件路径，默认 data/phds.db
        """
        # 自动补全 sqlite:/// 前缀（如果未传入）
        if db_path.startswith("sqlite:///"):
            self.db_url = db_path
        else:
            self.db_url = f"sqlite:///{db_path}"
        self.engine = create_engine(self.db_url, echo=False)
        self.Session = sessionmaker(bind=self.engine)

    def init_db(self) -> None:
        """创建所有表（如果不存在）。"""
        Base.metadata.create_all(self.engine)

    def create_tables(self) -> None:
        """创建所有表（如果不存在）— 别名，兼容旧调用。"""
        self.init_db()

    def drop_tables(self) -> None:
        """删除所有表（慎用）。"""
        Base.metadata.drop_all(self.engine)

    # ── 病历记录 CRUD ──────────────────────────────────────

    def add_bio_record(self, record_dict: Dict[str, Any]) -> BioRecordRow:
        """新增一条病历记录。

        Args:
            record_dict: 病历字典，至少包含 record_id, patient_pubkey_hash,
                         encrypted_data_url, data_hash。metadata 字段为嵌套 dict。

        Returns:
            插入的 BioRecordRow 对象
        """
        metadata = record_dict.get("metadata", {})
        if isinstance(metadata, dict):
            metadata_json = json.dumps(metadata, ensure_ascii=False)
        else:
            metadata_json = str(metadata)

        row = BioRecordRow(
            record_id=record_dict["record_id"],
            patient_pubkey_hash=record_dict["patient_pubkey_hash"],
            encrypted_data_url=record_dict["encrypted_data_url"],
            data_hash=record_dict["data_hash"],
            hospital_id=record_dict.get("hospital_id", ""),
            record_type=record_dict.get("record_type", ""),
            description=record_dict.get("description", ""),
            metadata_json=metadata_json,
            created_at=record_dict.get("created_at", time.time()),
        )
        with self.Session() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row

    def get_bio_records(self, patient_hash: str) -> List[BioRecordRow]:
        """按患者公钥哈希查询病历列表（任务要求的方法名）。

        Args:
            patient_hash: 患者公钥哈希

        Returns:
            BioRecordRow 列表
        """
        return self.get_bio_records_by_patient(patient_hash)

    def get_bio_records_by_patient(self, patient_hash: str) -> List[BioRecordRow]:
        """按患者公钥哈希查询病历列表。

        Args:
            patient_hash: 患者公钥哈希

        Returns:
            BioRecordRow 列表
        """
        with self.Session() as session:
            return (
                session.query(BioRecordRow)
                .filter(BioRecordRow.patient_pubkey_hash == patient_hash)
                .all()
            )

    def get_bio_record_by_id(self, record_id: str) -> Optional[BioRecordRow]:
        """按 record_id 查询单条病历。

        Args:
            record_id: 记录唯一 ID

        Returns:
            BioRecordRow 或 None
        """
        with self.Session() as session:
            return (
                session.query(BioRecordRow)
                .filter(BioRecordRow.record_id == record_id)
                .first()
            )

    def delete_bio_record(self, record_id: str) -> bool:
        """删除一条病历记录。

        Args:
            record_id: 记录唯一 ID

        Returns:
            True 表示删除成功，False 表示记录不存在
        """
        with self.Session() as session:
            row = (
                session.query(BioRecordRow)
                .filter(BioRecordRow.record_id == record_id)
                .first()
            )
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    # ── 授权事件 CRUD ──────────────────────────────────────

    def add_authorization(self, auth_dict: Dict[str, Any]) -> AuthorizationRow:
        """新增一条授权事件。

        Args:
            auth_dict: 授权事件字典

        Returns:
            插入的 AuthorizationRow 对象
        """
        row = AuthorizationRow(
            request_id=auth_dict.get("request_id", ""),
            patient_pubkey_hash=auth_dict.get("patient_pubkey_hash", ""),
            requester_id=auth_dict.get("requester_id", ""),
            session_key=auth_dict.get("session_key", ""),
            expire_at=auth_dict.get("expire_at", 0.0),
            status=auth_dict.get("status", "pending"),
            scope=auth_dict.get("scope", "read"),
            jti=auth_dict.get("jti", ""),
            created_at=auth_dict.get("created_at", time.time()),
            updated_at=auth_dict.get("updated_at", time.time()),
        )
        with self.Session() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row

    def get_authorization(self, request_id: str) -> Optional[AuthorizationRow]:
        """按 request_id 查询授权事件。

        Args:
            request_id: 请求 ID

        Returns:
            AuthorizationRow 或 None
        """
        with self.Session() as session:
            return (
                session.query(AuthorizationRow)
                .filter(AuthorizationRow.request_id == request_id)
                .first()
            )

    def get_authorization_by_jti(self, jti: str) -> Optional[AuthorizationRow]:
        """按 JWT ID 查询授权事件。

        Args:
            jti: JWT ID

        Returns:
            AuthorizationRow 或 None
        """
        with self.Session() as session:
            return (
                session.query(AuthorizationRow)
                .filter(AuthorizationRow.jti == jti)
                .first()
            )

    def update_authorization(
        self, request_id: str, updates: Dict[str, Any]
    ) -> bool:
        """更新授权事件字段。

        Args:
            request_id: 请求 ID
            updates:    要更新的字段字典

        Returns:
            True 表示更新成功，False 表示记录不存在
        """
        with self.Session() as session:
            row = (
                session.query(AuthorizationRow)
                .filter(AuthorizationRow.request_id == request_id)
                .first()
            )
            if row is None:
                return False
            for key, value in updates.items():
                if hasattr(row, key):
                    setattr(row, key, value)
            row.updated_at = time.time()
            session.commit()
            return True

    def list_authorizations_by_patient(
        self, patient_hash: str
    ) -> List[AuthorizationRow]:
        """按患者公钥哈希查询所有授权事件。

        Args:
            patient_hash: 患者公钥哈希

        Returns:
            AuthorizationRow 列表
        """
        with self.Session() as session:
            return (
                session.query(AuthorizationRow)
                .filter(AuthorizationRow.patient_pubkey_hash == patient_hash)
                .all()
            )

    # ── 审计日志 CRUD ──────────────────────────────────────

    def add_log(self, log_dict: Dict[str, Any]) -> AuthLogRow:
        """新增一条审计日志（任务要求的方法名）。

        Args:
            log_dict: 日志字典

        Returns:
            插入的 AuthLogRow 对象
        """
        return self.add_auth_log(log_dict)

    def add_auth_log(self, log_dict: Dict[str, Any]) -> AuthLogRow:
        """新增一条审计日志。

        Args:
            log_dict: 日志字典

        Returns:
            插入的 AuthLogRow 对象
        """
        row = AuthLogRow(
            event_id=log_dict.get("event_id", ""),
            timestamp=log_dict.get("timestamp", time.time()),
            action=log_dict.get("action", ""),
            requester_id=log_dict.get("requester_id", ""),
            patient_hash=log_dict.get("patient_hash", ""),
            jti=log_dict.get("jti", ""),
            scope=log_dict.get("scope", "read"),
            expire_at=log_dict.get("expire_at", 0.0),
        )
        with self.Session() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row

    def get_logs(self, limit: int = 100, offset: int = 0) -> List[AuthLogRow]:
        """分页查询审计日志（任务要求的方法名）。

        Args:
            limit:  返回条数上限
            offset: 偏移量

        Returns:
            AuthLogRow 列表
        """
        return self.list_auth_logs(limit=limit, offset=offset)

    def list_auth_logs(
        self, limit: int = 100, offset: int = 0
    ) -> List[AuthLogRow]:
        """分页查询审计日志。

        Args:
            limit:  返回条数上限
            offset: 偏移量

        Returns:
            AuthLogRow 列表
        """
        with self.Session() as session:
            return (
                session.query(AuthLogRow)
                .order_by(AuthLogRow.timestamp.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )

    def get_auth_logs_by_patient(
        self, patient_hash: str, limit: int = 100
    ) -> List[AuthLogRow]:
        """按患者公钥哈希查询审计日志。

        Args:
            patient_hash: 患者公钥哈希
            limit:        返回条数上限

        Returns:
            AuthLogRow 列表
        """
        with self.Session() as session:
            return (
                session.query(AuthLogRow)
                .filter(AuthLogRow.patient_hash == patient_hash)
                .order_by(AuthLogRow.timestamp.desc())
                .limit(limit)
                .all()
            )


# ── 向后兼容别名 ────────────────────────────────────────
Database = DatabaseManager
