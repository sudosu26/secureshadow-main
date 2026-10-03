"""
SECURESHADOW - SQLAlchemy Database Models
Mirrors the core domain entities for PostgreSQL persistence.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    JSON,
    ForeignKey,
    Table,
)
from sqlalchemy.orm import relationship

from .database import Base

# Many-to-Many association between Security Controls and Assets
control_assets_association = Table(
    "control_protected_assets",
    Base.metadata,
    Column("control_id", Integer, ForeignKey("security_controls.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", Integer, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
)


class UserModel(Base):
    """Admin and system users for JWT authentication."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AssetModel(Base):
    """Persisted representation of an infrastructure Asset."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(String(100), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(100), nullable=False)
    ip_address = Column(String(100), nullable=True)
    is_baseline = Column(Boolean, default=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    protecting_controls = relationship(
        "ControlModel",
        secondary=control_assets_association,
        back_populates="protected_assets",
    )


class ControlModel(Base):
    """Persisted representation of a Security Control."""
    __tablename__ = "security_controls"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String(100), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    control_type = Column(String(100), nullable=False)
    status = Column(String(50), default="active")
    is_baseline = Column(Boolean, default=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    protected_assets = relationship(
        "AssetModel",
        secondary=control_assets_association,
        back_populates="protecting_controls",
    )


class AssumptionModel(Base):
    """Persisted representation of a Security Assumption."""
    __tablename__ = "assumptions"

    id = Column(Integer, primary_key=True, index=True)
    assumption_id = Column(String(100), index=True, nullable=False)
    description = Column(String(500), nullable=False)
    related_control_id = Column(String(100), nullable=False)
    is_valid = Column(Boolean, default=True)
    is_baseline = Column(Boolean, default=True)
    last_checked = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PropertyModel(Base):
    """Persisted representation of a Security Property."""
    __tablename__ = "security_properties"

    id = Column(Integer, primary_key=True, index=True)
    property_id = Column(String(100), index=True, nullable=False)
    description = Column(String(500), nullable=False)
    control_id = Column(String(100), nullable=False)
    severity = Column(String(50), default="high")
    protection_level = Column(Float, default=100.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class PathModel(Base):
    """Persisted representation of a Communication Path."""
    __tablename__ = "communication_paths"

    id = Column(Integer, primary_key=True, index=True)
    path_id = Column(String(100), index=True, nullable=False)
    source_id = Column(String(100), nullable=False)
    destination_id = Column(String(100), nullable=False)
    protocol = Column(String(50), default="HTTPS")
    port = Column(Integer, nullable=True)
    passes_through = Column(JSON, default=list)
    is_baseline = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ChangeEventModel(Base):
    """Audit log of detected drift events."""
    __tablename__ = "change_events"

    id = Column(Integer, primary_key=True, index=True)
    change_type = Column(String(100), nullable=False)
    description = Column(String(500), nullable=False)
    affected_entities = Column(JSON, default=list)
    severity = Column(String(50), default="info")
    potentially_breaks_assumptions = Column(Boolean, default=False)
    affected_assumption_id = Column(String(100), nullable=True)
    affected_assumption_desc = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DecayReportModel(Base):
    """Persisted calculation report for protection decay."""
    __tablename__ = "decay_reports"

    id = Column(Integer, primary_key=True, index=True)
    property_id = Column(String(100), nullable=False)
    property_desc = Column(String(500), nullable=False)
    baseline_protection = Column(Float, default=100.0)
    current_protection = Column(Float, default=100.0)
    decay_percent = Column(Float, default=0.0)
    health_label = Column(String(50), default="HEALTHY")
    contributors = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RepairModel(Base):
    """Persisted repair recommendations."""
    __tablename__ = "repair_recommendations"

    id = Column(Integer, primary_key=True, index=True)
    repair_id = Column(String(100), nullable=False)
    description = Column(String(500), nullable=False)
    action_type = Column(String(100), nullable=False)
    total_cost = Column(Float, nullable=False)
    security_improvement = Column(Float, nullable=False)
    cost_effectiveness_ratio = Column(Float, default=0.0)
    is_recommended = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLogModel(Base):
    """Persisted event record of system activities, scans, and remediations."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, default="system")
    action = Column(String(100), nullable=False)
    entity_type = Column(String(100), nullable=True)
    entity_id = Column(String(100), nullable=True)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class RemediationModel(Base):
    """Tracked lifecycle record for applied security repairs."""
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)
    remediation_id = Column(String(100), index=True, nullable=False)
    repair_id = Column(String(100), nullable=False)
    description = Column(String(500), nullable=False)
    action_type = Column(String(100), nullable=False)
    status = Column(String(50), default="OPEN")  # OPEN, IN_PROGRESS, RESOLVED, FAILED
    applied_by = Column(String(100), nullable=False, default="admin")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)
    target_entity = Column(String(200), nullable=True)
    details = Column(JSON, default=dict)
