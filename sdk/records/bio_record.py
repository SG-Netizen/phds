"""
PHDS 生物医学记录数据结构（BioRecord）

每一条 BioRecord 代表患者拥有主权的一份健康数据：
  - record_id:          记录唯一标识
  - patient_pubkey_hash: 患者公钥哈希（匿名，即 patient_id）
  - encrypted_data_url:  加密数据存储地址（URL 或文件路径）
  - data_hash:          加密数据的 SHA-256 哈希（完整性校验）
  - metadata:           元数据（医院ID、记录类型、时间戳等）
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class RecordMetadata:
    """病历元数据。

    Attributes:
        hospital_id:  医院 / 数据源唯一标识
        record_type:  记录类型（如 "lab_report", "prescription", "imaging"）
        description:  人类可读描述
        created_at:   创建时间（Unix 时间戳）
        extra:        扩展字段
    """
    hospital_id: str = ""
    record_type: str = ""
    description: str = ""
    created_at: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hospital_id": self.hospital_id,
            "record_type": self.record_type,
            "description": self.description,
            "created_at": self.created_at,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RecordMetadata":
        return cls(
            hospital_id=d.get("hospital_id", ""),
            record_type=d.get("record_type", ""),
            description=d.get("description", ""),
            created_at=d.get("created_at", time.time()),
            extra=d.get("extra", {}),
        )


@dataclass
class BioRecord:
    """生物医学记录。

    所有字段必须显式提供，不可空。
    """
    record_id: str
    patient_pubkey_hash: str
    encrypted_data_url: str
    data_hash: str
    metadata: RecordMetadata

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "patient_pubkey_hash": self.patient_pubkey_hash,
            "encrypted_data_url": self.encrypted_data_url,
            "data_hash": self.data_hash,
            "metadata": self.metadata.to_dict(),
        }

    def to_json(self) -> str:
        """序列化为 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BioRecord":
        meta = d.get("metadata", {})
        if isinstance(meta, dict):
            metadata = RecordMetadata.from_dict(meta)
        else:
            metadata = meta
        return cls(
            record_id=d["record_id"],
            patient_pubkey_hash=d["patient_pubkey_hash"],
            encrypted_data_url=d["encrypted_data_url"],
            data_hash=d["data_hash"],
            metadata=metadata,
        )

    @classmethod
    def from_json(cls, s: str) -> "BioRecord":
        """从 JSON 字符串反序列化。"""
        return cls.from_dict(json.loads(s))

    @classmethod
    def create(
        cls,
        patient_pubkey_hash: str,
        encrypted_data_url: str,
        encrypted_data: bytes,
        metadata: RecordMetadata,
    ) -> "BioRecord":
        """工厂方法：创建一条 BioRecord。

        自动生成 record_id、计算加密数据的 SHA-256 哈希。

        Args:
            patient_pubkey_hash: 患者公钥哈希
            encrypted_data_url:  加密数据 URL
            encrypted_data:      加密数据（用于计算哈希）
            metadata:            元数据

        Returns:
            BioRecord 实例
        """
        return cls(
            record_id=uuid.uuid4().hex,
            patient_pubkey_hash=patient_pubkey_hash,
            encrypted_data_url=encrypted_data_url,
            data_hash=hashlib.sha256(encrypted_data).hexdigest(),
            metadata=metadata,
        )

    def verify_integrity(self, encrypted_data: bytes) -> bool:
        """验证加密数据的完整性。

        Args:
            encrypted_data: 加密数据

        Returns:
            True 表示哈希匹配
        """
        computed = hashlib.sha256(encrypted_data).hexdigest()
        return computed == self.data_hash
