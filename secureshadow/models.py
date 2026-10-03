"""
SECURESHADOW - Core Data Model
Defines the fundamental domain entities representing infrastructure,
security controls, assumptions, guarantees, and communication paths.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any


class Asset:
    """
    Represents any entity requiring protection (e.g. database, microservice, storage).
    """
    def __init__(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.asset_id = asset_id
        self.name = name
        self.asset_type = asset_type  # e.g., "database", "api", "service", "storage", "compute"
        self.ip_address = ip_address
        self.metadata = metadata or {}
        self.created_at = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"Asset({self.asset_id}: {self.name}, type={self.asset_type})"


class SecurityControl:
    """
    Represents an active security mechanism (e.g. WAF, Firewall, IAM Policy).
    """
    def __init__(
        self,
        control_id: str,
        name: str,
        control_type: str,
        status: str = "active",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.control_id = control_id
        self.name = name
        self.control_type = control_type  # e.g., "waf", "firewall", "iam", "mfa", "encryption"
        self.status = status              # "active", "inactive", "misconfigured"
        self.protects: List[Asset] = []   # Assets this control protects
        self.metadata = metadata or {}
        self.created_at = datetime.now()

    def add_protected_asset(self, asset: Asset) -> None:
        """Link an asset that this control protects."""
        if asset not in self.protects:
            self.protects.append(asset)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "control_type": self.control_type,
            "status": self.status,
            "protects": [a.asset_id for a in self.protects],
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"SecurityControl({self.control_id}: {self.name}, type={self.control_type}, status={self.status})"


class Assumption:
    """
    An explicit environmental precondition required for a security control to function effectively.
    Example: "All external HTTP traffic to Customer API must pass through the WAF"
    """
    def __init__(
        self,
        assumption_id: str,
        description: str,
        related_control_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.assumption_id = assumption_id
        self.description = description
        self.related_control_id = related_control_id
        self.is_valid: bool = True
        self.last_checked: Optional[datetime] = None
        self.metadata = metadata or {}

    def invalidate(self) -> None:
        """Mark this assumption as violated/broken."""
        self.is_valid = False
        self.last_checked = datetime.now()

    def validate(self) -> None:
        """Mark this assumption as valid."""
        self.is_valid = True
        self.last_checked = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assumption_id": self.assumption_id,
            "description": self.description,
            "related_control_id": self.related_control_id,
            "is_valid": self.is_valid,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        status = "VALID" if self.is_valid else "BROKEN"
        return f"Assumption({self.assumption_id}: [{status}] {self.description})"


class SecurityProperty:
    """
    The formal security guarantee a control and its assumptions are designed to provide.
    """
    def __init__(
        self,
        property_id: str,
        description: str,
        control_id: str,
        severity: str = "high",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.property_id = property_id
        self.description = description
        self.control_id = control_id
        self.severity = severity          # "critical", "high", "medium", "low"
        self.assumptions: List[Assumption] = []
        self.protection_level: float = 100.0  # Percentage (0 - 100)
        self.metadata = metadata or {}
        self.created_at = datetime.now()

    def add_assumption(self, assumption: Assumption) -> None:
        """Link an assumption required for this property to hold."""
        if assumption not in self.assumptions:
            self.assumptions.append(assumption)

    def recalculate_protection(self) -> float:
        """
        Recalculates protection level based on proportion of valid assumptions.
        """
        if len(self.assumptions) == 0:
            self.protection_level = 100.0
            return self.protection_level

        valid_count = sum(1 for a in self.assumptions if a.is_valid)
        self.protection_level = (valid_count / len(self.assumptions)) * 100.0
        return self.protection_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "property_id": self.property_id,
            "description": self.description,
            "control_id": self.control_id,
            "severity": self.severity,
            "assumptions": [a.assumption_id for a in self.assumptions],
            "protection_level": self.protection_level,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"SecurityProperty({self.property_id}: {self.description[:50]}... [{self.protection_level:.0f}%])"


class CommunicationPath:
    """
    Represents network communication or data flow between two assets.
    """
    def __init__(
        self,
        path_id: str,
        source: Asset,
        destination: Asset,
        protocol: str = "HTTPS",
        port: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.path_id = path_id
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.port = port
        self.passes_through: List[SecurityControl] = []
        self.metadata = metadata or {}
        self.created_at = datetime.now()

    def add_control(self, control: SecurityControl) -> None:
        """Add a security control that inspects or traverses this path."""
        if control not in self.passes_through:
            self.passes_through.append(control)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "source_id": self.source.asset_id,
            "destination_id": self.destination.asset_id,
            "protocol": self.protocol,
            "port": self.port,
            "passes_through": [c.control_id for c in self.passes_through],
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        controls = [c.name for c in self.passes_through]
        return f"Path({self.path_id}: {self.source.name} -> {self.destination.name}, controls={controls})"
