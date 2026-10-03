"""
SECURESHADOW - Pydantic Request and Response Schemas
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    expires_in_hours: int = 24


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class AssetSchema(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    protecting_controls: Optional[List[str]] = []


class ControlSchema(BaseModel):
    control_id: str
    name: str
    control_type: str
    status: str = "active"
    protects: Optional[List[str]] = []


class AssumptionSchema(BaseModel):
    assumption_id: str
    description: str
    related_control_id: str
    is_valid: bool = True


class PropertySchema(BaseModel):
    property_id: str
    description: str
    control_id: str
    severity: str = "critical"
    protection_level: float = 100.0


class PathSchema(BaseModel):
    path_id: str
    source_id: str
    destination_id: str
    protocol: str = "HTTPS"
    passes_through: Optional[List[str]] = []


class BaselineCaptureRequest(BaseModel):
    source: str = Field(default="demo", description="'demo' or 'terraform'")
    terraform_json: Optional[Dict[str, Any]] = None


class CurrentStateSubmitRequest(BaseModel):
    source: str = Field(default="demo_drift", description="'demo_drift' or 'terraform'")
    terraform_json: Optional[Dict[str, Any]] = None


class ChangeEventSchema(BaseModel):
    change_type: str
    description: str
    affected_entities: List[str]
    severity: str
    potentially_breaks_assumptions: bool
    affected_assumption_id: Optional[str] = None
    affected_assumption_desc: Optional[str] = None


class DriftDetectionResponse(BaseModel):
    total_changes: int
    changes: List[ChangeEventSchema]
    critical_count: int
    warning_count: int


class DecayContributorSchema(BaseModel):
    assumption_id: str
    assumption_desc: str
    change_desc: str
    impact_percent: float


class DecayReportResponse(BaseModel):
    property_id: str
    property_desc: str
    baseline_protection: float
    current_protection: float
    decay_percent: float
    health_label: str
    contributors: List[DecayContributorSchema]


class RepairCandidateSchema(BaseModel):
    repair_id: str
    description: str
    action_type: str
    total_cost: float
    security_improvement: float
    cost_effectiveness_ratio: float
    restored_assumptions: List[str]
    is_recommended: bool = False
    implementation_cost: float
    business_impact: float
    operational_risk: float
    implementation_time: float


class RepairResponse(BaseModel):
    total_candidates: int
    recommended_repair: Optional[RepairCandidateSchema] = None
    candidates: List[RepairCandidateSchema]
    restoration_target_percent: float = 50.0


class AuditLogSchema(BaseModel):
    id: int
    username: str
    action: str
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: str


class RemediationCreateRequest(BaseModel):
    repair_id: str
    description: str
    action_type: str
    target_entity: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class RemediationUpdateRequest(BaseModel):
    status: str  # OPEN, IN_PROGRESS, RESOLVED, FAILED


class RemediationSchema(BaseModel):
    id: int
    remediation_id: str
    repair_id: str
    description: str
    action_type: str
    status: str
    applied_by: str
    created_at: str
    resolved_at: Optional[str] = None
    target_entity: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AssetCreateRequest(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    ip_address: Optional[str] = None


class ControlCreateRequest(BaseModel):
    control_id: str
    name: str
    control_type: str
    status: str = "active"
    protects: Optional[List[str]] = []


class PathCreateRequest(BaseModel):
    path_id: str
    source_id: str
    destination_id: str
    protocol: str = "HTTPS"
    passes_through: Optional[List[str]] = []
