"""
SECURESHADOW - REST API Routes
Implements endpoints for baseline capture, drift detection, decay analysis,
repair generation, remediation lifecycle tracking, audit logging, and asset inventory.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db.database import get_db
from ..db.models import (
    UserModel,
    AssetModel,
    ControlModel,
    AssumptionModel,
    PropertyModel,
    PathModel,
    ChangeEventModel,
    DecayReportModel,
    RepairModel,
    AuditLogModel,
    RemediationModel,
)
from ..db.schemas import (
    LoginRequest,
    TokenResponse,
    AssetSchema,
    ControlSchema,
    AssumptionSchema,
    PropertySchema,
    PathSchema,
    BaselineCaptureRequest,
    CurrentStateSubmitRequest,
    DriftDetectionResponse,
    ChangeEventSchema,
    DecayReportResponse,
    DecayContributorSchema,
    RepairResponse,
    RepairCandidateSchema,
    AuditLogSchema,
    RemediationCreateRequest,
    RemediationUpdateRequest,
    RemediationSchema,
    AssetCreateRequest,
    ControlCreateRequest,
    PathCreateRequest,
    ChangePasswordRequest,
)
from .auth import verify_password, create_access_token, get_current_user, hash_password
from ..models import Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath
from ..graph import SecurityGraph
from ..drift import DriftDetector, AssumptionAnalyzer, ChangeEvent
from ..decay import DecayCalculator, DecayResult
from ..repair import RepairOptimizer
from ..scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario
from ..loaders.terraform import TerraformLoader

router = APIRouter(prefix="/api/v1")

# Global in-memory active engine state synchronized with DB
engine_state = {
    "baseline_graph": None,
    "current_graph": None,
    "assumptions": [],
    "properties": [],
    "analyzed_changes": [],
    "latest_decay": None,
    "repair_candidates": [],
    "best_repair": None,
}


def record_audit_log(
    db: Session,
    username: str,
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLogModel:
    """Helper to persist audit events."""
    entry = AuditLogModel(
        username=username,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details or {},
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and issue JWT."""
    user = db.query(UserModel).filter(UserModel.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token(data={"sub": user.username})
    record_audit_log(db, username=user.username, action="USER_LOGIN", entity_type="USER", entity_id=user.username)
    return TokenResponse(access_token=token, username=user.username)


@router.get("/auth/me")
def get_me(user: UserModel = Depends(get_current_user)):
    """Get active authenticated user identity."""
    return {"username": user.username, "is_admin": user.is_admin}


@router.post("/auth/change-password")
def change_password(
    req: ChangePasswordRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Rotate credentials for the currently authenticated user."""
    if not verify_password(req.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )
    if len(req.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters long.",
        )
    user.hashed_password = hash_password(req.new_password)
    db.commit()
    record_audit_log(
        db,
        username=user.username,
        action="USER_PASSWORD_CHANGED",
        entity_type="USER",
        entity_id=user.username,
    )
    return {"status": "success", "message": "Password updated successfully."}


@router.post("/baseline")
def create_baseline(
    req: BaselineCaptureRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """
    Establish the known-good baseline architecture.
    Accepts source='demo' or source='terraform' with payload.
    """
    # Clear previous baseline records
    db.query(AssetModel).filter(AssetModel.is_baseline == True).delete()
    db.query(ControlModel).filter(ControlModel.is_baseline == True).delete()
    db.query(AssumptionModel).filter(AssumptionModel.is_baseline == True).delete()
    db.query(PropertyModel).delete()
    db.query(PathModel).filter(PathModel.is_baseline == True).delete()
    db.query(ChangeEventModel).delete()
    db.query(DecayReportModel).delete()
    db.query(RepairModel).delete()
    db.commit()

    if req.source == "terraform" and req.terraform_json:
        loader = TerraformLoader()
        graph, asms, props = loader.build_graph_from_json(req.terraform_json)
        engine_state["baseline_graph"] = graph
        engine_state["assumptions"] = asms
        engine_state["properties"] = props
    else:
        # Canonical Demo Baseline
        scenario = create_demo_scenario()
        graph = build_baseline_graph(scenario)
        engine_state["baseline_graph"] = graph
        engine_state["assumptions"] = scenario["assumptions"]
        engine_state["properties"] = scenario["properties"]

    # Persist graph nodes to database
    for node_id, data in engine_state["baseline_graph"].graph.nodes(data=True):
        ntype = data.get("type")
        if ntype == "asset":
            asset_m = AssetModel(
                asset_id=node_id,
                name=data.get("name", node_id),
                asset_type=data.get("asset_type", "unknown"),
                ip_address=data.get("ip"),
                is_baseline=True,
            )
            db.add(asset_m)
        elif ntype == "control":
            ctrl_m = ControlModel(
                control_id=node_id,
                name=data.get("name", node_id),
                control_type=data.get("control_type", "unknown"),
                status=data.get("status", "active"),
                is_baseline=True,
            )
            db.add(ctrl_m)

    # Persist assumptions
    for a in engine_state["assumptions"]:
        db.add(AssumptionModel(
            assumption_id=a.assumption_id,
            description=a.description,
            related_control_id=a.related_control_id,
            is_valid=a.is_valid,
            is_baseline=True,
        ))

    # Persist properties
    for p in engine_state["properties"]:
        db.add(PropertyModel(
            property_id=p.property_id,
            description=p.description,
            control_id=p.control_id,
            severity=p.severity,
            protection_level=p.protection_level,
        ))

    # Persist edges
    for u, v, data in engine_state["baseline_graph"].graph.edges(data=True):
        if data.get("relationship") == "COMMUNICATES":
            db.add(PathModel(
                path_id=data.get("path_id", f"{u}->{v}"),
                source_id=u,
                destination_id=v,
                protocol=data.get("protocol", "TCP"),
                is_baseline=True,
            ))

    # Flush to ensure all asset/control rows exist before linking
    db.flush()

    # Populate control-asset many-to-many from PROTECTS edges
    for u, v, data in engine_state["baseline_graph"].graph.edges(data=True):
        if data.get("relationship") == "PROTECTS":
            ctrl_m = db.query(ControlModel).filter(ControlModel.control_id == u).first()
            asset_m = db.query(AssetModel).filter(AssetModel.asset_id == v).first()
            if ctrl_m and asset_m and asset_m not in ctrl_m.protected_assets:
                ctrl_m.protected_assets.append(asset_m)

    db.commit()

    stats = engine_state["baseline_graph"].get_graph_stats()
    record_audit_log(
        db,
        username=user.username,
        action="BASELINE_CAPTURED",
        entity_type="BASELINE",
        details={"source": req.source, "nodes": stats["total_nodes"], "edges": stats["total_edges"]},
    )

    return {
        "status": "baseline_established",
        "total_nodes": stats["total_nodes"],
        "total_edges": stats["total_edges"],
        "node_types": stats["node_types"],
        "assumptions_count": len(engine_state["assumptions"]),
        "properties_count": len(engine_state["properties"]),
    }


@router.get("/baseline")
def get_baseline(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Retrieve overview of current baseline architecture."""
    if not engine_state["baseline_graph"]:
        assets = db.query(AssetModel).filter(AssetModel.is_baseline == True).all()
        if not assets:
            raise HTTPException(status_code=404, detail="No baseline established yet. Call POST /baseline first.")
        # Reconstruct from demo if available
        scenario = create_demo_scenario()
        engine_state["baseline_graph"] = build_baseline_graph(scenario)
        engine_state["assumptions"] = scenario["assumptions"]
        engine_state["properties"] = scenario["properties"]

    stats = engine_state["baseline_graph"].get_graph_stats()
    return {
        "is_active": True,
        "stats": stats,
        "assumptions": [a.description for a in engine_state["assumptions"]],
        "properties": [p.description for p in engine_state["properties"]],
    }


@router.post("/current")
def submit_current_state(
    req: CurrentStateSubmitRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Submit current/drifted infrastructure state."""
    if not engine_state["baseline_graph"]:
        raise HTTPException(status_code=400, detail="Cannot submit current state before establishing baseline.")

    if req.source == "terraform" and req.terraform_json:
        loader = TerraformLoader()
        graph, _, _ = loader.build_graph_from_json(req.terraform_json)
        engine_state["current_graph"] = graph
    else:
        # Canonical Demo Drift (adds AI Analytics Service bypassing WAF)
        scenario = create_demo_scenario()
        drifted = create_drifted_scenario(scenario)
        engine_state["current_graph"] = drifted["current_graph"]

    stats = engine_state["current_graph"].get_graph_stats()
    record_audit_log(
        db,
        username=user.username,
        action="CURRENT_STATE_SUBMITTED",
        entity_type="CURRENT_STATE",
        details={"source": req.source, "nodes": stats["total_nodes"], "edges": stats["total_edges"]},
    )
    return {
        "status": "current_state_recorded",
        "total_nodes": stats["total_nodes"],
        "total_edges": stats["total_edges"],
        "node_types": stats["node_types"],
    }


def execute_detection_pipeline(db: Session, username: str = "system") -> DriftDetectionResponse:
    """Core detection logic callable by HTTP routes and background scheduler."""
    base = engine_state["baseline_graph"]
    curr = engine_state["current_graph"]

    if not base or not curr:
        raise ValueError("Baseline and current graph must both be set before running detection.")

    detector = DriftDetector()
    detector.set_baseline(base)
    raw_changes = detector.detect_drift(curr)

    analyzer = AssumptionAnalyzer(engine_state["assumptions"])
    analyzed_changes = analyzer.analyze(raw_changes, current_graph=curr, baseline_graph=base)
    engine_state["analyzed_changes"] = analyzed_changes

    # Persist changes to database
    db.query(ChangeEventModel).delete()
    for c in analyzed_changes:
        db.add(ChangeEventModel(
            change_type=c.change_type,
            description=c.description,
            affected_entities=c.affected_entities,
            severity=c.severity,
            potentially_breaks_assumptions=c.potentially_breaks_assumptions,
            affected_assumption_id=getattr(c, "affected_assumption_id", None),
            affected_assumption_desc=getattr(c, "affected_assumption_desc", None),
        ))
    db.commit()

    crit = sum(1 for c in analyzed_changes if c.severity == "critical")
    warn = sum(1 for c in analyzed_changes if c.severity == "warning")

    # Automatically compute and store decay report
    if engine_state["properties"]:
        calculator = DecayCalculator()
        target_property = engine_state["properties"][0]
        decay_result = calculator.calculate(target_property, analyzed_changes)
        engine_state["latest_decay"] = decay_result

        db.query(DecayReportModel).delete()
        db.add(DecayReportModel(
            property_id=decay_result.property_id,
            property_desc=decay_result.property_desc,
            baseline_protection=decay_result.baseline_protection,
            current_protection=decay_result.current_protection,
            decay_percent=decay_result.decay_percent,
            health_label=decay_result.get_health_label(),
            contributors=[c.to_dict() for c in decay_result.contributors],
        ))
        db.commit()

    record_audit_log(
        db,
        username=username,
        action="DRIFT_DETECTED",
        entity_type="SCAN",
        details={"total_changes": len(analyzed_changes), "critical": crit, "warning": warn},
    )

    return DriftDetectionResponse(
        total_changes=len(analyzed_changes),
        changes=[ChangeEventSchema(**c.to_dict()) for c in analyzed_changes],
        critical_count=crit,
        warning_count=warn,
    )


@router.post("/detect", response_model=DriftDetectionResponse)
def detect_drift(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Run drift detection diff between baseline and current graphs."""
    if not engine_state["baseline_graph"]:
        raise HTTPException(status_code=400, detail="Baseline graph not set.")
    if not engine_state["current_graph"]:
        raise HTTPException(status_code=400, detail="Current graph not set. Call POST /current first.")

    return execute_detection_pipeline(db, username=user.username)


@router.get("/decay", response_model=DecayReportResponse)
def get_decay_report(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Calculate and return the Protection Decay Report for the primary security property."""
    if not engine_state["properties"]:
        raise HTTPException(status_code=400, detail="No security properties defined in baseline.")

    calculator = DecayCalculator()
    target_property = engine_state["properties"][0]
    decay_result = calculator.calculate(target_property, engine_state["analyzed_changes"])
    engine_state["latest_decay"] = decay_result

    # Persist report
    db.query(DecayReportModel).delete()
    db.add(DecayReportModel(
        property_id=decay_result.property_id,
        property_desc=decay_result.property_desc,
        baseline_protection=decay_result.baseline_protection,
        current_protection=decay_result.current_protection,
        decay_percent=decay_result.decay_percent,
        health_label=decay_result.get_health_label(),
        contributors=[c.to_dict() for c in decay_result.contributors],
    ))
    db.commit()

    return DecayReportResponse(
        property_id=decay_result.property_id,
        property_desc=decay_result.property_desc,
        baseline_protection=decay_result.baseline_protection,
        current_protection=decay_result.current_protection,
        decay_percent=decay_result.decay_percent,
        health_label=decay_result.get_health_label(),
        contributors=[DecayContributorSchema(**c.to_dict()) for c in decay_result.contributors],
    )


@router.get("/repairs", response_model=RepairResponse)
def get_repair_recommendations(
    min_improvement: float = 50.0,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Generate, cost, and rank repair candidates, recommending the minimum-cost option."""
    if not engine_state["latest_decay"]:
        if engine_state["properties"]:
            calculator = DecayCalculator()
            engine_state["latest_decay"] = calculator.calculate(
                engine_state["properties"][0],
                engine_state["analyzed_changes"],
            )
        else:
            raise HTTPException(status_code=400, detail="Cannot generate repairs without baseline and decay analysis.")

    optimizer = RepairOptimizer()
    candidates = optimizer.generate_candidates(
        engine_state["latest_decay"],
        engine_state["analyzed_changes"],
        engine_state["current_graph"],
    )
    best = optimizer.find_minimum_cost_repair(min_security_improvement=min_improvement)
    engine_state["repair_candidates"] = candidates
    engine_state["best_repair"] = best

    # Persist repairs
    db.query(RepairModel).delete()
    for c in candidates:
        db.add(RepairModel(
            repair_id=c.repair_id,
            description=c.description,
            action_type=c.action_type,
            total_cost=c.total_cost,
            security_improvement=c.security_improvement,
            cost_effectiveness_ratio=c.cost_effectiveness_ratio,
            is_recommended=(c == best),
        ))
    db.commit()

    record_audit_log(
        db,
        username=user.username,
        action="REPAIRS_OPTIMIZED",
        entity_type="REPAIRS",
        details={"total_candidates": len(candidates), "recommended": best.repair_id if best else None},
    )

    return RepairResponse(
        total_candidates=len(candidates),
        recommended_repair=RepairCandidateSchema(
            **best.to_dict(),
            is_recommended=True,
        ) if best else None,
        candidates=[
            RepairCandidateSchema(
                **c.to_dict(),
                is_recommended=(c == best),
            ) for c in candidates
        ],
        restoration_target_percent=min_improvement,
    )


# -------------------------------------------------------------------------
# REMEDIATION TRACKING LIFECYCLE (PART B)
# -------------------------------------------------------------------------

@router.post("/remediations", response_model=RemediationSchema)
def apply_remediation(
    req: RemediationCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """
    Apply a recommended repair candidate, creating a tracked remediation record.
    Initial state is 'IN_PROGRESS'.
    """
    remediation_id = f"REM-{uuid.uuid4().hex[:8].upper()}"
    rem = RemediationModel(
        remediation_id=remediation_id,
        repair_id=req.repair_id,
        description=req.description,
        action_type=req.action_type,
        status="IN_PROGRESS",
        applied_by=user.username,
        target_entity=req.target_entity,
        details=req.details or {},
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)

    record_audit_log(
        db,
        username=user.username,
        action="REPAIR_APPLIED",
        entity_type="REMEDIATION",
        entity_id=remediation_id,
        details={"repair_id": req.repair_id, "action_type": req.action_type},
    )

    return RemediationSchema(
        id=rem.id,
        remediation_id=rem.remediation_id,
        repair_id=rem.repair_id,
        description=rem.description,
        action_type=rem.action_type,
        status=rem.status,
        applied_by=rem.applied_by,
        created_at=rem.created_at.isoformat(),
        resolved_at=rem.resolved_at.isoformat() if rem.resolved_at else None,
        target_entity=rem.target_entity,
        details=rem.details,
    )


@router.get("/remediations", response_model=List[RemediationSchema])
def list_remediations(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List all tracked remediation actions and their statuses."""
    items = db.query(RemediationModel).order_by(RemediationModel.created_at.desc()).all()
    return [
        RemediationSchema(
            id=r.id,
            remediation_id=r.remediation_id,
            repair_id=r.repair_id,
            description=r.description,
            action_type=r.action_type,
            status=r.status,
            applied_by=r.applied_by,
            created_at=r.created_at.isoformat(),
            resolved_at=r.resolved_at.isoformat() if r.resolved_at else None,
            target_entity=r.target_entity,
            details=r.details,
        )
        for r in items
    ]


@router.patch("/remediations/{remediation_id}", response_model=RemediationSchema)
def update_remediation_status(
    remediation_id: str,
    req: RemediationUpdateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Manually update remediation status (OPEN, IN_PROGRESS, RESOLVED, FAILED)."""
    rem = db.query(RemediationModel).filter(RemediationModel.remediation_id == remediation_id).first()
    if not rem:
        raise HTTPException(status_code=404, detail=f"Remediation '{remediation_id}' not found.")

    rem.status = req.status
    if req.status == "RESOLVED":
        rem.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(rem)

    record_audit_log(
        db,
        username=user.username,
        action="REMEDIATION_STATUS_UPDATED",
        entity_type="REMEDIATION",
        entity_id=remediation_id,
        details={"new_status": req.status},
    )

    return RemediationSchema(
        id=rem.id,
        remediation_id=rem.remediation_id,
        repair_id=rem.repair_id,
        description=rem.description,
        action_type=rem.action_type,
        status=rem.status,
        applied_by=rem.applied_by,
        created_at=rem.created_at.isoformat(),
        resolved_at=rem.resolved_at.isoformat() if rem.resolved_at else None,
        target_entity=rem.target_entity,
        details=rem.details,
    )


@router.post("/remediations/{remediation_id}/verify")
def verify_remediation(
    remediation_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """
    Executes real verification against the active infrastructure graph:
    1. Applies the remediation fix to the current graph (e.g. removes bypass edge or isolates rogue node).
    2. Re-runs drift detection and decay calculation.
    3. If the violation/decay clears, marks status as 'RESOLVED'.
    """
    rem = db.query(RemediationModel).filter(RemediationModel.remediation_id == remediation_id).first()
    if not rem:
        raise HTTPException(status_code=404, detail=f"Remediation '{remediation_id}' not found.")

    curr_graph = engine_state["current_graph"]
    base_graph = engine_state["baseline_graph"]

    if not curr_graph or not base_graph:
        raise HTTPException(status_code=400, detail="Baseline and current graphs must be initialized to verify remediation.")

    # Apply the structural remediation to the current graph
    if rem.action_type == "remove_path":
        # Look for rogue edges in current graph that are not in baseline
        edges_to_remove = []
        for u, v, data in curr_graph.graph.edges(data=True):
            if not base_graph.graph.has_edge(u, v):
                edges_to_remove.append((u, v))
        for u, v in edges_to_remove:
            curr_graph.graph.remove_edge(u, v)

        # Also decommission isolated rogue assets that were introduced with the path
        nodes_to_remove = [
            n for n in list(curr_graph.graph.nodes())
            if not base_graph.graph.has_node(n) and curr_graph.graph.degree(n) == 0
        ]
        for n in nodes_to_remove:
            curr_graph.graph.remove_node(n)

    elif rem.action_type == "add_control":
        # Add control coverage or connect WAF
        for node in curr_graph.graph.nodes():
            if curr_graph.graph.nodes[node].get("type") == "control":
                # Ensure control has protects relationship to protected assets
                for asset in base_graph.graph.nodes():
                    if base_graph.graph.nodes[asset].get("type") == "asset":
                        curr_graph.graph.add_edge(node, asset, relationship="PROTECTS", label="PROTECTS")

    elif rem.action_type == "restrict_access":
        # Remove direct bypass paths to database
        edges_to_remove = []
        for u, v, data in curr_graph.graph.edges(data=True):
            if "database" in curr_graph.graph.nodes[v].get("asset_type", "") and not base_graph.graph.has_edge(u, v):
                edges_to_remove.append((u, v))
        for u, v in edges_to_remove:
            curr_graph.graph.remove_edge(u, v)

    # Re-run drift detection
    detector = DriftDetector()
    detector.set_baseline(base_graph)
    changes = detector.detect_drift(curr_graph)

    analyzer = AssumptionAnalyzer(engine_state["assumptions"])
    analyzed_changes = analyzer.analyze(changes, current_graph=curr_graph, baseline_graph=base_graph)
    engine_state["analyzed_changes"] = analyzed_changes

    # Re-calculate decay
    calculator = DecayCalculator()
    target_property = engine_state["properties"][0]
    decay_result = calculator.calculate(target_property, analyzed_changes)
    engine_state["latest_decay"] = decay_result

    # Evaluate resolution
    if decay_result.decay_percent == 0.0 or len(decay_result.broken_assumptions) == 0:
        rem.status = "RESOLVED"
        rem.resolved_at = datetime.now(timezone.utc)
        message = "Verification successful: Underlying bypass removed and security assumptions restored."
    else:
        rem.status = "IN_PROGRESS"
        message = f"Verification incomplete: Protection decay remains at -{decay_result.decay_percent:.1f}%."

    db.commit()
    db.refresh(rem)

    record_audit_log(
        db,
        username=user.username,
        action="REMEDIATION_VERIFIED",
        entity_type="REMEDIATION",
        entity_id=remediation_id,
        details={
            "status": rem.status,
            "remaining_decay": decay_result.decay_percent,
            "current_protection": decay_result.current_protection,
        },
    )

    return {
        "remediation_id": rem.remediation_id,
        "status": rem.status,
        "current_protection": decay_result.current_protection,
        "decay_percent": decay_result.decay_percent,
        "health_label": decay_result.get_health_label(),
        "message": message,
    }


# -------------------------------------------------------------------------
# AUDIT LOGS ENDPOINT (PART B)
# -------------------------------------------------------------------------

@router.get("/audit-logs", response_model=List[AuditLogSchema])
def list_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Retrieve chronologically ordered audit logs from the database."""
    logs = db.query(AuditLogModel).order_by(AuditLogModel.timestamp.desc()).limit(limit).all()
    return [
        AuditLogSchema(
            id=log.id,
            username=log.username,
            action=log.action,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            details=log.details,
            timestamp=log.timestamp.isoformat(),
        )
        for log in logs
    ]


# -------------------------------------------------------------------------
# INVENTORY MANAGEMENT CRUD (PART A.3)
# -------------------------------------------------------------------------

@router.get("/assets", response_model=List[AssetSchema])
def list_assets(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List all assets tracked in database."""
    assets = db.query(AssetModel).all()
    out = []
    for a in assets:
        controls = [c.name for c in a.protecting_controls]
        out.append(AssetSchema(
            asset_id=a.asset_id,
            name=a.name,
            asset_type=a.asset_type,
            ip_address=a.ip_address,
            protecting_controls=controls,
        ))
    return out


@router.post("/assets", response_model=AssetSchema)
def create_asset(
    req: AssetCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Create a new asset in the inventory."""
    existing = db.query(AssetModel).filter(AssetModel.asset_id == req.asset_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Asset with ID '{req.asset_id}' already exists.")

    asset_m = AssetModel(
        asset_id=req.asset_id,
        name=req.name,
        asset_type=req.asset_type,
        ip_address=req.ip_address,
        is_baseline=False,
    )
    db.add(asset_m)
    db.commit()
    db.refresh(asset_m)

    # If current graph exists, update in-memory graph
    if engine_state["current_graph"]:
        engine_state["current_graph"].add_asset(
            Asset(req.asset_id, req.name, req.asset_type, req.ip_address)
        )

    record_audit_log(
        db,
        username=user.username,
        action="ASSET_CREATED",
        entity_type="ASSET",
        entity_id=req.asset_id,
        details={"name": req.name, "type": req.asset_type},
    )

    return AssetSchema(
        asset_id=asset_m.asset_id,
        name=asset_m.name,
        asset_type=asset_m.asset_type,
        ip_address=asset_m.ip_address,
        protecting_controls=[],
    )


@router.delete("/assets/{asset_id}")
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Delete an asset from the inventory."""
    asset_m = db.query(AssetModel).filter(AssetModel.asset_id == asset_id).first()
    if not asset_m:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    db.delete(asset_m)
    db.commit()

    if engine_state["current_graph"] and asset_id in engine_state["current_graph"].graph:
        engine_state["current_graph"].graph.remove_node(asset_id)

    record_audit_log(
        db,
        username=user.username,
        action="ASSET_DELETED",
        entity_type="ASSET",
        entity_id=asset_id,
    )
    return {"status": "deleted", "asset_id": asset_id}


@router.get("/controls", response_model=List[ControlSchema])
def list_controls(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List all security controls tracked in database."""
    controls = db.query(ControlModel).all()
    out = []
    for c in controls:
        protected = [a.name for a in c.protected_assets]
        out.append(ControlSchema(
            control_id=c.control_id,
            name=c.name,
            control_type=c.control_type,
            status=c.status,
            protects=protected,
        ))
    return out


@router.post("/controls", response_model=ControlSchema)
def create_control(
    req: ControlCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Create a new security control."""
    existing = db.query(ControlModel).filter(ControlModel.control_id == req.control_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Control with ID '{req.control_id}' already exists.")

    ctrl_m = ControlModel(
        control_id=req.control_id,
        name=req.name,
        control_type=req.control_type,
        status=req.status,
        is_baseline=False,
    )
    db.add(ctrl_m)
    db.commit()
    db.refresh(ctrl_m)

    if engine_state["current_graph"]:
        sc = SecurityControl(req.control_id, req.name, req.control_type, req.status)
        engine_state["current_graph"].add_control(sc)

    record_audit_log(
        db,
        username=user.username,
        action="CONTROL_CREATED",
        entity_type="CONTROL",
        entity_id=req.control_id,
        details={"name": req.name, "type": req.control_type},
    )

    return ControlSchema(
        control_id=ctrl_m.control_id,
        name=ctrl_m.name,
        control_type=ctrl_m.control_type,
        status=ctrl_m.status,
        protects=[],
    )


@router.delete("/controls/{control_id}")
def delete_control(
    control_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Delete a security control."""
    ctrl_m = db.query(ControlModel).filter(ControlModel.control_id == control_id).first()
    if not ctrl_m:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found.")

    db.delete(ctrl_m)
    db.commit()

    if engine_state["current_graph"] and control_id in engine_state["current_graph"].graph:
        engine_state["current_graph"].graph.remove_node(control_id)

    record_audit_log(
        db,
        username=user.username,
        action="CONTROL_DELETED",
        entity_type="CONTROL",
        entity_id=control_id,
    )
    return {"status": "deleted", "control_id": control_id}


@router.get("/paths", response_model=List[PathSchema])
def list_paths(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List communication paths tracked in database."""
    paths = db.query(PathModel).all()
    return [
        PathSchema(
            path_id=p.path_id,
            source_id=p.source_id,
            destination_id=p.destination_id,
            protocol=p.protocol,
            passes_through=p.passes_through or [],
        )
        for p in paths
    ]


@router.post("/paths", response_model=PathSchema)
def create_path(
    req: PathCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Create a new communication path between assets."""
    path_m = PathModel(
        path_id=req.path_id,
        source_id=req.source_id,
        destination_id=req.destination_id,
        protocol=req.protocol,
        passes_through=req.passes_through or [],
        is_baseline=False,
    )
    db.add(path_m)
    db.commit()
    db.refresh(path_m)

    if engine_state["current_graph"]:
        engine_state["current_graph"].graph.add_edge(
            req.source_id,
            req.destination_id,
            relationship="COMMUNICATES",
            protocol=req.protocol,
            path_id=req.path_id,
        )

    record_audit_log(
        db,
        username=user.username,
        action="PATH_CREATED",
        entity_type="PATH",
        entity_id=req.path_id,
        details={"source": req.source_id, "destination": req.destination_id},
    )

    return PathSchema(
        path_id=path_m.path_id,
        source_id=path_m.source_id,
        destination_id=path_m.destination_id,
        protocol=path_m.protocol,
        passes_through=path_m.passes_through or [],
    )


@router.delete("/paths/{path_id}")
def delete_path(
    path_id: str,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Delete a communication path."""
    path_m = db.query(PathModel).filter(PathModel.path_id == path_id).first()
    if not path_m:
        raise HTTPException(status_code=404, detail=f"Path '{path_id}' not found.")

    src, dst = path_m.source_id, path_m.destination_id
    db.delete(path_m)
    db.commit()

    if engine_state["current_graph"] and engine_state["current_graph"].graph.has_edge(src, dst):
        engine_state["current_graph"].graph.remove_edge(src, dst)

    record_audit_log(
        db,
        username=user.username,
        action="PATH_DELETED",
        entity_type="PATH",
        entity_id=path_id,
    )
    return {"status": "deleted", "path_id": path_id}


@router.get("/properties", response_model=List[PropertySchema])
def list_properties(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List security properties defined in active baseline."""
    props = db.query(PropertyModel).all()
    return [
        PropertySchema(
            property_id=p.property_id,
            description=p.description,
            control_id=p.control_id,
            severity=p.severity,
            protection_level=p.protection_level,
        )
        for p in props
    ]
