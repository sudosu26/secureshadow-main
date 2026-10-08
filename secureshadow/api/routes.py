"""
SECURESHADOW - REST API Routes
Implements endpoints for baseline capture, drift detection, decay analysis,
repair generation, remediation lifecycle tracking, audit logging, and asset inventory.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session, selectinload
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

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
    GraphSnapshotModel,
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
from ..services.graph_state import (
    clone_graph,
    deserialize_graph,
    load_graph_snapshot,
    persist_security_definitions,
    persist_graph_snapshot,
    serialize_graph,
)

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


def load_persisted_engine_state(db: Session) -> None:
    """Reload authoritative topology and security definitions from the database."""
    baseline_graph = load_graph_snapshot(db, "baseline")
    if baseline_graph is None:
        baseline_assets = db.query(AssetModel).filter(AssetModel.is_baseline.is_(True)).all()
        if not baseline_assets:
            engine_state.update({
                "baseline_graph": None,
                "current_graph": None,
                "assumptions": [],
                "properties": [],
                "analyzed_changes": [],
                "latest_decay": None,
            })
            return

        baseline_graph = SecurityGraph()
        for asset in baseline_assets:
            baseline_graph.graph.add_node(
                asset.asset_id,
                type="asset",
                name=asset.name,
                asset_type=asset.asset_type,
                ip=asset.ip_address,
            )
        for control in db.query(ControlModel).filter(ControlModel.is_baseline.is_(True)).all():
            baseline_graph.graph.add_node(
                control.control_id,
                type="control",
                name=control.name,
                control_type=control.control_type,
                status=control.status,
            )
            for asset in control.protected_assets:
                if asset.is_baseline:
                    baseline_graph.graph.add_edge(
                        control.control_id,
                        asset.asset_id,
                        relationship="PROTECTS",
                        label="PROTECTS",
                    )
        for assumption in db.query(AssumptionModel).filter(AssumptionModel.is_baseline.is_(True)).all():
            baseline_graph.graph.add_node(
                assumption.assumption_id,
                type="assumption",
                description=assumption.description,
                is_valid=assumption.is_valid,
            )
            baseline_graph.graph.add_edge(
                assumption.assumption_id,
                assumption.related_control_id,
                relationship="DEPENDS_ON",
                label="DEPENDS_ON",
            )
        for path in db.query(PathModel).filter(PathModel.is_baseline.is_(True)).all():
            baseline_graph.graph.add_edge(
                path.source_id,
                path.destination_id,
                relationship="COMMUNICATES",
                protocol=path.protocol,
                path_id=path.path_id,
                label=path.protocol,
            )
            for control_id in path.passes_through or []:
                baseline_graph.graph.add_edge(
                    path.source_id,
                    control_id,
                    relationship="PASSES_THROUGH",
                    label="PASSES_THROUGH",
                )
        baseline_graph._invalidate_caches()
        persist_graph_snapshot(db, "baseline", baseline_graph)

    current_graph = load_graph_snapshot(db, "current")
    if current_graph is None:
        current_graph = baseline_graph
        persist_graph_snapshot(db, "current", current_graph)
    baseline_snapshot = db.get(GraphSnapshotModel, "baseline")
    baseline_data = baseline_snapshot.graph_data if baseline_snapshot else {}
    assumptions = []
    for definition in baseline_data.get("assumptions", []):
        assumption = Assumption(
            definition["assumption_id"],
            definition["description"],
            definition["related_control_id"],
        )
        assumption.is_valid = definition.get("is_valid", True)
        assumptions.append(assumption)
    if not assumptions:
        for assumption_model in db.query(AssumptionModel).filter(AssumptionModel.is_baseline.is_(True)).all():
            assumption = Assumption(
                assumption_model.assumption_id,
                assumption_model.description,
                assumption_model.related_control_id,
            )
            assumption.is_valid = assumption_model.is_valid
            assumption.last_checked = assumption_model.last_checked
            assumptions.append(assumption)

    assumption_by_id = {assumption.assumption_id: assumption for assumption in assumptions}
    properties = []
    for definition in baseline_data.get("properties", []):
        security_property = SecurityProperty(
            definition["property_id"],
            definition["description"],
            definition["control_id"],
            definition.get("severity", "high"),
        )
        for assumption_id in definition.get("assumptions", []):
            if assumption_id in assumption_by_id:
                security_property.add_assumption(assumption_by_id[assumption_id])
        properties.append(security_property)
    if not properties:
        for property_model in db.query(PropertyModel).all():
            security_property = SecurityProperty(
                property_model.property_id,
                property_model.description,
                property_model.control_id,
                property_model.severity,
            )
            for assumption in assumptions:
                if assumption.related_control_id == property_model.control_id:
                    security_property.add_assumption(assumption)
            properties.append(security_property)

    if db.new or db.dirty:
        db.commit()
    engine_state.update({
        "baseline_graph": baseline_graph,
        "current_graph": current_graph,
        "assumptions": list(assumption_by_id.values()),
        "properties": properties,
        "analyzed_changes": [],
        "latest_decay": None,
        "repair_candidates": [],
        "best_repair": None,
    })


def persist_current_inventory_delta(
    db: Session,
    baseline_graph: SecurityGraph,
    current_graph: SecurityGraph,
) -> None:
    """Keep relational inventory rows for current-only assets, controls, and paths in sync."""
    db.query(AssetModel).filter(AssetModel.is_baseline.is_(False)).delete(synchronize_session=False)
    db.query(ControlModel).filter(ControlModel.is_baseline.is_(False)).delete(synchronize_session=False)
    db.query(PathModel).filter(PathModel.is_baseline.is_(False)).delete(synchronize_session=False)

    for node_id, data in current_graph.graph.nodes(data=True):
        if node_id in baseline_graph.graph:
            continue
        if data.get("type") == "asset":
            db.add(AssetModel(
                asset_id=node_id,
                name=data.get("name", node_id),
                asset_type=data.get("asset_type", "unknown"),
                ip_address=data.get("ip"),
                is_baseline=False,
            ))
        elif data.get("type") == "control":
            db.add(ControlModel(
                control_id=node_id,
                name=data.get("name", node_id),
                control_type=data.get("control_type", "unknown"),
                status=data.get("status", "active"),
                is_baseline=False,
            ))

    for source, destination, data in current_graph.graph.edges(data=True):
        if (
            data.get("relationship") == "COMMUNICATES"
            and not baseline_graph.graph.has_edge(source, destination)
        ):
            db.add(PathModel(
                path_id=data.get("path_id", f"{source}->{destination}"),
                source_id=source,
                destination_id=destination,
                protocol=data.get("protocol", "HTTPS"),
                is_baseline=False,
            ))


def assets_from_graph(graph: SecurityGraph) -> List[AssetSchema]:
    return [
        AssetSchema(
            asset_id=node_id,
            name=data.get("name", node_id),
            asset_type=data.get("asset_type", "unknown"),
            ip_address=data.get("ip"),
            protecting_controls=[
                graph.graph.nodes[control_id].get("name", control_id)
                for control_id in graph.find_controls_protecting(node_id)
            ],
        )
        for node_id, data in graph.graph.nodes(data=True)
        if data.get("type") == "asset"
    ]


def controls_from_graph(graph: SecurityGraph) -> List[ControlSchema]:
    return [
        ControlSchema(
            control_id=node_id,
            name=data.get("name", node_id),
            control_type=data.get("control_type", "unknown"),
            status=data.get("status", "active"),
            protects=[
                graph.graph.nodes[asset_id].get("name", asset_id)
                for _, asset_id, edge_data in graph.graph.out_edges(node_id, data=True)
                if edge_data.get("relationship") == "PROTECTS"
            ],
        )
        for node_id, data in graph.graph.nodes(data=True)
        if data.get("type") == "control"
    ]


def paths_from_graph(graph: SecurityGraph) -> List[PathSchema]:
    paths = []
    for source, destination, data in graph.graph.edges(data=True):
        if data.get("relationship") != "COMMUNICATES":
            continue
        passes_through = [
            control_id
            for _, control_id, edge_data in graph.graph.out_edges(source, data=True)
            if edge_data.get("relationship") == "PASSES_THROUGH"
        ]
        paths.append(PathSchema(
            path_id=data.get("path_id", f"{source}->{destination}"),
            source_id=source,
            destination_id=destination,
            protocol=data.get("protocol", "HTTPS"),
            passes_through=passes_through,
        ))
    return paths


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
@limiter.limit("10/minute")
def login(request: Request, req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user and issue JWT. Rate limited to 10 attempts per minute."""
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
@limiter.limit("5/minute")
def change_password(
    request: Request,
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

    engine_state["current_graph"] = engine_state["baseline_graph"]
    engine_state["analyzed_changes"] = []
    engine_state["latest_decay"] = None

    # Persist graph nodes to database
    assets_to_add = []
    controls_to_add = []
    for node_id, data in engine_state["baseline_graph"].graph.nodes(data=True):
        ntype = data.get("type")
        if ntype == "asset":
            assets_to_add.append(AssetModel(
                asset_id=node_id,
                name=data.get("name", node_id),
                asset_type=data.get("asset_type", "unknown"),
                ip_address=data.get("ip"),
                is_baseline=True,
            ))
        elif ntype == "control":
            controls_to_add.append(ControlModel(
                control_id=node_id,
                name=data.get("name", node_id),
                control_type=data.get("control_type", "unknown"),
                status=data.get("status", "active"),
                is_baseline=True,
            ))
    db.add_all(assets_to_add)
    db.add_all(controls_to_add)

    # Persist assumptions
    db.add_all([
        AssumptionModel(
            assumption_id=a.assumption_id,
            description=a.description,
            related_control_id=a.related_control_id,
            is_valid=a.is_valid,
            is_baseline=True,
        )
        for a in engine_state["assumptions"]
    ])

    # Persist properties
    db.add_all([
        PropertyModel(
            property_id=p.property_id,
            description=p.description,
            control_id=p.control_id,
            severity=p.severity,
            protection_level=p.protection_level,
        )
        for p in engine_state["properties"]
    ])

    # Persist edges
    paths_to_add = []
    for u, v, data in engine_state["baseline_graph"].graph.edges(data=True):
        if data.get("relationship") == "COMMUNICATES":
            paths_to_add.append(PathModel(
                path_id=data.get("path_id", f"{u}->{v}"),
                source_id=u,
                destination_id=v,
                protocol=data.get("protocol", "TCP"),
                is_baseline=True,
            ))
    db.add_all(paths_to_add)

    # Flush to ensure all asset/control rows exist before linking
    db.flush()

    # Populate control-asset many-to-many from PROTECTS edges in bulk.
    controls_by_id = {
        control.control_id: control
        for control in db.query(ControlModel)
        .options(selectinload(ControlModel.protected_assets))
        .filter(ControlModel.is_baseline.is_(True))
        .all()
    }
    assets_by_id = {
        asset.asset_id: asset
        for asset in db.query(AssetModel).filter(AssetModel.is_baseline.is_(True)).all()
    }
    for u, v, data in engine_state["baseline_graph"].graph.edges(data=True):
        if data.get("relationship") == "PROTECTS":
            ctrl_m = controls_by_id.get(u)
            asset_m = assets_by_id.get(v)
            if ctrl_m and asset_m and asset_m not in ctrl_m.protected_assets:
                ctrl_m.protected_assets.append(asset_m)

    persist_current_inventory_delta(
        db,
        engine_state["baseline_graph"],
        engine_state["current_graph"],
    )
    persist_graph_snapshot(db, "baseline", engine_state["baseline_graph"])
    persist_graph_snapshot(db, "current", engine_state["current_graph"])
    persist_security_definitions(db, engine_state["assumptions"], engine_state["properties"])
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
    load_persisted_engine_state(db)
    if not engine_state["baseline_graph"]:
        assets = db.query(AssetModel).filter(AssetModel.is_baseline == True).all()
        if not assets:
            raise HTTPException(status_code=404, detail="No baseline established yet. Call POST /baseline first.")

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
    load_persisted_engine_state(db)
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

    persist_current_inventory_delta(
        db,
        engine_state["baseline_graph"],
        engine_state["current_graph"],
    )
    persist_graph_snapshot(db, "current", engine_state["current_graph"])
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


def calculate_security_state(
    base: SecurityGraph,
    curr: SecurityGraph,
    assumptions: List[Assumption],
    properties: List[SecurityProperty],
) -> tuple[List[ChangeEvent], Optional[DecayResult], DriftDetectionResponse]:
    """Calculate drift and decay exclusively from the supplied baseline/current state."""
    detector = DriftDetector()
    detector.set_baseline(base)
    raw_changes = detector.detect_drift(curr)

    analyzer = AssumptionAnalyzer(assumptions)
    analyzed_changes = analyzer.analyze(raw_changes, current_graph=curr, baseline_graph=base)

    crit = sum(1 for c in analyzed_changes if c.severity == "critical")
    warn = sum(1 for c in analyzed_changes if c.severity == "warning")

    decay_result = None
    if properties:
        decay_result = DecayCalculator().calculate(properties[0], analyzed_changes)

    response = DriftDetectionResponse(
        total_changes=len(analyzed_changes),
        changes=[ChangeEventSchema(**change.to_dict()) for change in analyzed_changes],
        critical_count=crit,
        warning_count=warn,
    )
    return analyzed_changes, decay_result, response


def execute_detection_pipeline(
    db: Session,
    username: str = "system",
    record_audit: bool = True,
) -> DriftDetectionResponse:
    """Recompute and atomically persist drift and decay from authoritative state."""
    base = engine_state["baseline_graph"]
    curr = engine_state["current_graph"]
    if not base or not curr:
        raise ValueError("Baseline and current graph must both be set before running detection.")

    analyzed_changes, decay_result, response = calculate_security_state(
        base,
        curr,
        engine_state["assumptions"],
        engine_state["properties"],
    )

    try:
        db.query(ChangeEventModel).delete(synchronize_session=False)
        db.add_all([
            ChangeEventModel(
                change_type=change.change_type,
                description=change.description,
                affected_entities=change.affected_entities,
                severity=change.severity,
                potentially_breaks_assumptions=change.potentially_breaks_assumptions,
                affected_assumption_id=change.affected_assumption_id,
                affected_assumption_desc=change.affected_assumption_desc,
            )
            for change in analyzed_changes
        ])
        if decay_result is not None:
            db.query(DecayReportModel).delete(synchronize_session=False)
            db.add(DecayReportModel(
            property_id=decay_result.property_id,
            property_desc=decay_result.property_desc,
            baseline_protection=decay_result.baseline_protection,
            current_protection=decay_result.current_protection,
            decay_percent=decay_result.decay_percent,
            health_label=decay_result.get_health_label(),
            contributors=[c.to_dict() for c in decay_result.contributors],
            ))
        if record_audit:
            db.add(AuditLogModel(
                username=username,
                action="DRIFT_DETECTED",
                entity_type="SCAN",
                details={
                    "total_changes": response.total_changes,
                    "critical": response.critical_count,
                    "warning": response.warning_count,
                },
            ))
        db.commit()
    except Exception:
        db.rollback()
        raise

    engine_state["analyzed_changes"] = analyzed_changes
    engine_state["latest_decay"] = decay_result
    return response


@router.post("/detect", response_model=DriftDetectionResponse)
def detect_drift(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Run drift detection diff between baseline and current graphs."""
    load_persisted_engine_state(db)
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
    load_persisted_engine_state(db)
    if not engine_state["baseline_graph"] or not engine_state["current_graph"]:
        raise HTTPException(status_code=400, detail="Baseline and current graphs must be initialized before decay analysis.")
    if not engine_state["properties"]:
        raise HTTPException(status_code=400, detail="No security properties defined in baseline.")

    execute_detection_pipeline(db, username=user.username, record_audit=False)
    decay_result = engine_state["latest_decay"]
    if decay_result is None:
        raise HTTPException(status_code=400, detail="Decay calculation is unavailable for the current state.")

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
    load_persisted_engine_state(db)
    if not engine_state["baseline_graph"] or not engine_state["current_graph"]:
        raise HTTPException(status_code=400, detail="Baseline and current state are required to generate repairs.")
    if not engine_state["properties"]:
        raise HTTPException(status_code=400, detail="Cannot generate repairs without a security property.")
    execute_detection_pipeline(db, username=user.username, record_audit=False)

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
    repair = db.query(RepairModel).filter(RepairModel.repair_id == req.repair_id).first()
    if repair is None or repair.action_type != req.action_type:
        raise HTTPException(
            status_code=400,
            detail="The selected repair is no longer available or does not match the requested action.",
        )

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
    Apply a supported repair to current state, persist it, and atomically refresh metrics.
    The approved baseline is deliberately immutable during repair verification.
    """
    load_persisted_engine_state(db)
    rem = db.query(RemediationModel).filter(RemediationModel.remediation_id == remediation_id).first()
    if not rem:
        raise HTTPException(status_code=404, detail=f"Remediation '{remediation_id}' not found.")

    curr_graph = engine_state["current_graph"]
    base_graph = engine_state["baseline_graph"]

    if not curr_graph or not base_graph:
        raise HTTPException(status_code=400, detail="Baseline and current graphs must be initialized to verify remediation.")

    repaired_graph = deserialize_graph(serialize_graph(curr_graph))
    previous_stats = curr_graph.get_graph_stats()
    comm_edges = [
        (source, target, dict(data))
        for source, target, data in repaired_graph.graph.edges(data=True)
        if data.get("relationship") == "COMMUNICATES"
    ]
    new_edges = [
        edge for edge in comm_edges
        if not base_graph.graph.has_edge(edge[0], edge[1])
    ]

    target_path_edges = [
        edge for edge in comm_edges
        if rem.target_entity and edge[2].get("path_id") == rem.target_entity
    ]
    if not target_path_edges and rem.target_entity and "->" in rem.target_entity:
        target_source, target_destination = rem.target_entity.split("->", 1)
        target_path_edges = [
            edge for edge in comm_edges
            if edge[0] == target_source and edge[1] == target_destination
        ]

    edges_to_remove: list[tuple[str, str]] = []
    if rem.action_type in ("remove_path", "restrict_access"):
        if target_path_edges:
            edges_to_remove = [(source, target) for source, target, _ in target_path_edges]
        elif rem.action_type == "restrict_access":
            edges_to_remove = [
                (source, target)
                for source, target, _ in new_edges
                if "database" in str(repaired_graph.graph.nodes[target].get("asset_type", "")).lower()
            ]
        else:
            edges_to_remove = [(source, target) for source, target, _ in new_edges]

        if not edges_to_remove:
            raise HTTPException(
                status_code=409,
                detail="No matching non-baseline communication path remains for this repair.",
            )
        repaired_graph.graph.remove_edges_from(edges_to_remove)
        for node_id in list(repaired_graph.graph.nodes):
            if node_id not in base_graph.graph and repaired_graph.graph.degree(node_id) == 0:
                repaired_graph.graph.remove_node(node_id)
    elif rem.action_type == "add_control":
        if not new_edges:
            raise HTTPException(status_code=409, detail="No uninspected path remains to protect.")
        relevant_assumption_ids = {
            change.affected_assumption_id
            for change in engine_state["analyzed_changes"]
            if change.potentially_breaks_assumptions and change.affected_assumption_id
        }
        relevant_control_ids = {
            assumption.related_control_id
            for assumption in engine_state["assumptions"]
            if assumption.assumption_id in relevant_assumption_ids
        }
        active_controls = [
            control_id
            for control_id in relevant_control_ids
            if control_id in repaired_graph.graph
            and repaired_graph.graph.nodes[control_id].get("status", "active") == "active"
        ]
        if not active_controls:
            raise HTTPException(
                status_code=409,
                detail="No active control associated with the violated assumption is available.",
            )
        for source, _, _ in new_edges:
            repaired_graph.graph.add_edge(
                source,
                active_controls[0],
                relationship="PASSES_THROUGH",
                label="PASSES_THROUGH",
            )
    else:
        raise HTTPException(
            status_code=422,
            detail=f"Repair action '{rem.action_type}' is not supported by the current state model.",
        )

    repaired_graph._invalidate_caches()
    analyzed_changes, decay_result, drift_response = calculate_security_state(
        base_graph,
        repaired_graph,
        engine_state["assumptions"],
        engine_state["properties"],
    )
    if decay_result is None:
        raise HTTPException(status_code=400, detail="No security property is configured for verification.")

    repaired = not any(change.potentially_breaks_assumptions for change in analyzed_changes)
    if repaired:
        rem.status = "RESOLVED"
        rem.resolved_at = datetime.now(timezone.utc)
        message = "Verification successful: the repaired current state no longer violates the relevant assumptions."
    else:
        rem.status = "IN_PROGRESS"
        rem.resolved_at = None
        message = f"Verification incomplete: protection decay remains at -{decay_result.decay_percent:.1f}%."

    repaired_stats = repaired_graph.get_graph_stats()
    try:
        persist_current_inventory_delta(db, base_graph, repaired_graph)
        persist_graph_snapshot(db, "current", repaired_graph)
        db.query(ChangeEventModel).delete(synchronize_session=False)
        db.add_all([
            ChangeEventModel(
                change_type=change.change_type,
                description=change.description,
                affected_entities=change.affected_entities,
                severity=change.severity,
                potentially_breaks_assumptions=change.potentially_breaks_assumptions,
                affected_assumption_id=change.affected_assumption_id,
                affected_assumption_desc=change.affected_assumption_desc,
            )
            for change in analyzed_changes
        ])
        db.query(DecayReportModel).delete(synchronize_session=False)
        db.add(DecayReportModel(
            property_id=decay_result.property_id,
            property_desc=decay_result.property_desc,
            baseline_protection=decay_result.baseline_protection,
            current_protection=decay_result.current_protection,
            decay_percent=decay_result.decay_percent,
            health_label=decay_result.get_health_label(),
            contributors=[contributor.to_dict() for contributor in decay_result.contributors],
        ))
        db.add(AuditLogModel(
            username=user.username,
            action="REPAIR_EXECUTED",
            entity_type="REMEDIATION",
            entity_id=remediation_id,
            details={
                "repair_id": rem.repair_id,
                "action_type": rem.action_type,
                "target_entity": rem.target_entity,
                "previous_state": previous_stats,
                "new_state": repaired_stats,
                "removed_paths": [
                    f"{source}->{target}" for source, target in edges_to_remove
                ],
                "result": rem.status,
                "affected_metrics": {
                    "total_changes": drift_response.total_changes,
                    "critical_count": drift_response.critical_count,
                    "warning_count": drift_response.warning_count,
                    "current_protection": decay_result.current_protection,
                    "decay_percent": decay_result.decay_percent,
                    "health_label": decay_result.get_health_label(),
                },
            },
        ))
        db.commit()
        db.refresh(rem)
    except Exception:
        db.rollback()
        raise

    engine_state["current_graph"] = repaired_graph
    engine_state["analyzed_changes"] = analyzed_changes
    engine_state["latest_decay"] = decay_result
    assets_response = assets_from_graph(repaired_graph)
    controls_response = controls_from_graph(repaired_graph)
    paths_response = paths_from_graph(repaired_graph)
    remediations_response = list_remediations(db, user)
    dashboard_metrics = {
        "assets": len(assets_response),
        "controls": len(controls_response),
        "remediations": len(remediations_response),
        "properties": len(engine_state["properties"]),
        "open_remediations": sum(
            remediation.status != "RESOLVED"
            for remediation in remediations_response
        ),
        "current_protection": decay_result.current_protection,
        "decay_percent": decay_result.decay_percent,
        "health_label": decay_result.get_health_label(),
    }

    return {
        "remediation_id": rem.remediation_id,
        "status": rem.status,
        "current_protection": decay_result.current_protection,
        "decay_percent": decay_result.decay_percent,
        "health_label": decay_result.get_health_label(),
        "total_changes": drift_response.total_changes,
        "critical_count": drift_response.critical_count,
        "warning_count": drift_response.warning_count,
        "assets": [asset.model_dump() for asset in assets_response],
        "controls": [control.model_dump() for control in controls_response],
        "paths": [path.model_dump() for path in paths_response],
        "changes": [change.model_dump() for change in drift_response.changes],
        "dashboard": dashboard_metrics,
        "decay": DecayReportResponse(
            property_id=decay_result.property_id,
            property_desc=decay_result.property_desc,
            baseline_protection=decay_result.baseline_protection,
            current_protection=decay_result.current_protection,
            decay_percent=decay_result.decay_percent,
            health_label=decay_result.get_health_label(),
            contributors=[DecayContributorSchema(**item.to_dict()) for item in decay_result.contributors],
        ).model_dump(),
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
    """List assets from the persisted current topology, falling back to inventory rows."""
    load_persisted_engine_state(db)
    graph = engine_state["current_graph"]
    if graph:
        return assets_from_graph(graph)
    assets = (
        db.query(AssetModel)
        .options(selectinload(AssetModel.protecting_controls))
        .all()
    )
    return [
        AssetSchema(
            asset_id=asset.asset_id,
            name=asset.name,
            asset_type=asset.asset_type,
            ip_address=asset.ip_address,
            protecting_controls=[control.name for control in asset.protecting_controls],
        )
        for asset in assets
    ]


@router.post("/assets", response_model=AssetSchema)
def create_asset(
    req: AssetCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Create a new asset in the inventory."""
    load_persisted_engine_state(db)
    existing = db.query(AssetModel).filter(AssetModel.asset_id == req.asset_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Asset with ID '{req.asset_id}' already exists.")

    current_graph = engine_state["current_graph"]
    updated_graph = clone_graph(current_graph) if current_graph else None
    if updated_graph:
        updated_graph.add_asset(Asset(req.asset_id, req.name, req.asset_type, req.ip_address))

    asset_m = AssetModel(
        asset_id=req.asset_id,
        name=req.name,
        asset_type=req.asset_type,
        ip_address=req.ip_address,
        is_baseline=False,
    )
    db.add(asset_m)
    if updated_graph:
        persist_graph_snapshot(db, "current", updated_graph)
    db.add(AuditLogModel(
        username=user.username,
        action="ASSET_CREATED",
        entity_type="ASSET",
        entity_id=req.asset_id,
        details={"name": req.name, "type": req.asset_type},
    ))
    try:
        db.commit()
        db.refresh(asset_m)
    except Exception:
        db.rollback()
        raise
    if updated_graph:
        engine_state["current_graph"] = updated_graph

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
    load_persisted_engine_state(db)
    asset_m = db.query(AssetModel).filter(AssetModel.asset_id == asset_id).first()
    if not asset_m:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    current_graph = engine_state["current_graph"]
    updated_graph = clone_graph(current_graph) if current_graph else None
    if updated_graph and asset_id in updated_graph.graph:
        updated_graph.graph.remove_node(asset_id)
        updated_graph._invalidate_caches()

    db.delete(asset_m)
    if updated_graph:
        persist_graph_snapshot(db, "current", updated_graph)
    db.add(AuditLogModel(
        username=user.username,
        action="ASSET_DELETED",
        entity_type="ASSET",
        entity_id=asset_id,
    ))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    if updated_graph:
        engine_state["current_graph"] = updated_graph
    return {"status": "deleted", "asset_id": asset_id}


@router.get("/controls", response_model=List[ControlSchema])
def list_controls(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List controls and protection relationships from the persisted current topology."""
    load_persisted_engine_state(db)
    graph = engine_state["current_graph"]
    if graph:
        return controls_from_graph(graph)
    controls = (
        db.query(ControlModel)
        .options(selectinload(ControlModel.protected_assets))
        .all()
    )
    return [
        ControlSchema(
            control_id=control.control_id,
            name=control.name,
            control_type=control.control_type,
            status=control.status,
            protects=[asset.name for asset in control.protected_assets],
        )
        for control in controls
    ]


@router.post("/controls", response_model=ControlSchema)
def create_control(
    req: ControlCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Create a new security control."""
    load_persisted_engine_state(db)
    existing = db.query(ControlModel).filter(ControlModel.control_id == req.control_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Control with ID '{req.control_id}' already exists.")

    current_graph = engine_state["current_graph"]
    updated_graph = clone_graph(current_graph) if current_graph else None
    protected_models = []
    for asset_id in req.protects or []:
        asset_model = db.query(AssetModel).filter(AssetModel.asset_id == asset_id).first()
        if asset_model is None:
            raise HTTPException(status_code=404, detail=f"Protected asset '{asset_id}' not found.")
        protected_models.append(asset_model)
    sc = SecurityControl(req.control_id, req.name, req.control_type, req.status)
    if updated_graph:
        for asset_id in req.protects or []:
            if asset_id not in updated_graph.graph or updated_graph.graph.nodes[asset_id].get("type") != "asset":
                raise HTTPException(status_code=404, detail=f"Protected asset '{asset_id}' not found in current state.")
            asset_data = updated_graph.graph.nodes[asset_id]
            sc.add_protected_asset(Asset(
                asset_id,
                asset_data.get("name", asset_id),
                asset_data.get("asset_type", "unknown"),
                asset_data.get("ip"),
            ))
        updated_graph.add_control(sc)

    ctrl_m = ControlModel(
        control_id=req.control_id,
        name=req.name,
        control_type=req.control_type,
        status=req.status,
        is_baseline=False,
    )
    ctrl_m.protected_assets.extend(protected_models)
    db.add(ctrl_m)
    if updated_graph:
        persist_graph_snapshot(db, "current", updated_graph)
    db.add(AuditLogModel(
        username=user.username,
        action="CONTROL_CREATED",
        entity_type="CONTROL",
        entity_id=req.control_id,
        details={"name": req.name, "type": req.control_type, "protects": req.protects or []},
    ))
    try:
        db.commit()
        db.refresh(ctrl_m)
    except Exception:
        db.rollback()
        raise
    if updated_graph:
        engine_state["current_graph"] = updated_graph

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
    load_persisted_engine_state(db)
    ctrl_m = db.query(ControlModel).filter(ControlModel.control_id == control_id).first()
    if not ctrl_m:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found.")

    current_graph = engine_state["current_graph"]
    updated_graph = clone_graph(current_graph) if current_graph else None
    if updated_graph and control_id in updated_graph.graph:
        updated_graph.graph.remove_node(control_id)
        updated_graph._invalidate_caches()

    db.delete(ctrl_m)
    if updated_graph:
        persist_graph_snapshot(db, "current", updated_graph)
    db.add(AuditLogModel(
        username=user.username,
        action="CONTROL_DELETED",
        entity_type="CONTROL",
        entity_id=control_id,
    ))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    if updated_graph:
        engine_state["current_graph"] = updated_graph
    return {"status": "deleted", "control_id": control_id}


@router.get("/paths", response_model=List[PathSchema])
def list_paths(
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """List communication paths from the persisted current topology."""
    load_persisted_engine_state(db)
    graph = engine_state["current_graph"]
    if graph:
        return paths_from_graph(graph)
    return [
        PathSchema(
            path_id=path.path_id,
            source_id=path.source_id,
            destination_id=path.destination_id,
            protocol=path.protocol,
            passes_through=path.passes_through or [],
        )
        for path in db.query(PathModel).all()
    ]


@router.post("/paths", response_model=PathSchema)
def create_path(
    req: PathCreateRequest,
    db: Session = Depends(get_db),
    user: UserModel = Depends(get_current_user),
):
    """Create a new communication path between assets."""
    load_persisted_engine_state(db)
    current_graph = engine_state["current_graph"]
    updated_graph = clone_graph(current_graph) if current_graph else None
    if updated_graph:
        for asset_id in (req.source_id, req.destination_id):
            if asset_id not in updated_graph.graph or updated_graph.graph.nodes[asset_id].get("type") != "asset":
                raise HTTPException(status_code=404, detail=f"Path asset '{asset_id}' not found in current state.")
        updated_graph.graph.add_edge(
            req.source_id,
            req.destination_id,
            relationship="COMMUNICATES",
            protocol=req.protocol,
            path_id=req.path_id,
            label=req.protocol,
        )
        for control_id in req.passes_through or []:
            if control_id not in updated_graph.graph or updated_graph.graph.nodes[control_id].get("type") != "control":
                raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found in current state.")
            updated_graph.graph.add_edge(
                req.source_id,
                control_id,
                relationship="PASSES_THROUGH",
                label="PASSES_THROUGH",
            )
        updated_graph._invalidate_caches()

    path_m = PathModel(
        path_id=req.path_id,
        source_id=req.source_id,
        destination_id=req.destination_id,
        protocol=req.protocol,
        passes_through=req.passes_through or [],
        is_baseline=False,
    )
    db.add(path_m)
    if updated_graph:
        persist_graph_snapshot(db, "current", updated_graph)
    db.add(AuditLogModel(
        username=user.username,
        action="PATH_CREATED",
        entity_type="PATH",
        entity_id=req.path_id,
        details={"source": req.source_id, "destination": req.destination_id},
    ))
    try:
        db.commit()
        db.refresh(path_m)
    except Exception:
        db.rollback()
        raise
    if updated_graph:
        engine_state["current_graph"] = updated_graph

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
    load_persisted_engine_state(db)
    path_m = db.query(PathModel).filter(PathModel.path_id == path_id).first()
    if not path_m:
        raise HTTPException(status_code=404, detail=f"Path '{path_id}' not found.")

    src, dst = path_m.source_id, path_m.destination_id
    current_graph = engine_state["current_graph"]
    updated_graph = clone_graph(current_graph) if current_graph else None
    if updated_graph and updated_graph.graph.has_edge(src, dst):
        edge_data = updated_graph.graph.edges[src, dst]
        if edge_data.get("path_id") == path_id:
            updated_graph.graph.remove_edge(src, dst)
            updated_graph._invalidate_caches()

    db.delete(path_m)
    if updated_graph:
        persist_graph_snapshot(db, "current", updated_graph)
    db.add(AuditLogModel(
        username=user.username,
        action="PATH_DELETED",
        entity_type="PATH",
        entity_id=path_id,
    ))
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    if updated_graph:
        engine_state["current_graph"] = updated_graph
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
