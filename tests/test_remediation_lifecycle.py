"""
Tests for closed-loop Remediation Tracking and Verification lifecycle.
"""

import pytest
from fastapi.testclient import TestClient
from secureshadow.api.app import app
from secureshadow.api.routes import engine_state
from secureshadow.db.database import init_db, SessionLocal
from secureshadow.db.models import (
    AuditLogModel,
    GraphSnapshotModel,
    PathModel,
    RemediationModel,
)
from secureshadow.api.auth import create_access_token, seed_admin_user

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    seed_admin_user(db)
    db.close()


def get_token():
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secureshadowadmin"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_full_remediation_closed_loop():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Establish baseline & drift
    client.post("/api/v1/baseline", json={"source": "demo"}, headers=headers)
    client.post("/api/v1/current", json={"source": "demo_drift"}, headers=headers)

    # 2. Detect & verify decay is present
    res_detect = client.post("/api/v1/detect", headers=headers)
    assert res_detect.status_code == 200
    assert res_detect.json()["total_changes"] == 2

    res_decay = client.get("/api/v1/decay", headers=headers)
    assert res_decay.json()["decay_percent"] == 52.5
    assert res_decay.json()["health_label"] == "AT RISK"

    # 3. Get recommended repair
    res_repairs = client.get("/api/v1/repairs?min_improvement=50.0", headers=headers)
    rec = res_repairs.json()["recommended_repair"]
    assert rec["action_type"] == "remove_path"

    # 4. Apply repair as tracked remediation
    res_apply = client.post(
        "/api/v1/remediations",
        json={
            "repair_id": rec["repair_id"],
            "description": rec["description"],
            "action_type": rec["action_type"],
            "target_entity": "path-003",
        },
        headers=headers,
    )
    assert res_apply.status_code == 200
    rem = res_apply.json()
    assert rem["status"] == "IN_PROGRESS"
    rem_id = rem["remediation_id"]

    # 5. List remediations
    res_list = client.get("/api/v1/remediations", headers=headers)
    assert len(res_list.json()) >= 1

    # 6. Verify remediation (closed-loop verification)
    res_verify = client.post(f"/api/v1/remediations/{rem_id}/verify", headers=headers)
    assert res_verify.status_code == 200
    data_v = res_verify.json()
    assert data_v["status"] == "RESOLVED"
    assert data_v["decay_percent"] == 0.0
    assert data_v["current_protection"] == 100.0
    assert data_v["total_changes"] == 0
    assert all(asset["asset_id"] != "asset-003" for asset in data_v["assets"])
    assert all(path["path_id"] != "path-003" for path in data_v["paths"])
    assert data_v["dashboard"]["current_protection"] == 100.0

    # 7. Confirm remediation is persisted as RESOLVED in DB
    res_rems_after = client.get("/api/v1/remediations", headers=headers)
    verified_item = next(r for r in res_rems_after.json() if r["remediation_id"] == rem_id)
    assert verified_item["status"] == "RESOLVED"
    assert verified_item["resolved_at"] is not None

    # Repair changes durable current state, not the approved baseline.
    db = SessionLocal()
    try:
        baseline_snapshot = db.get(GraphSnapshotModel, "baseline")
        current_snapshot = db.get(GraphSnapshotModel, "current")
        assert baseline_snapshot is not None
        assert current_snapshot is not None
        assert any(edge.get("path_id") == "path-002" for edge in baseline_snapshot.graph_data["edges"])
        assert not any(edge.get("path_id") == "path-003" for edge in current_snapshot.graph_data["edges"])
        assert db.query(PathModel).filter(PathModel.path_id == "path-003").count() == 0
        repair_log = db.query(AuditLogModel).filter(
            AuditLogModel.action == "REPAIR_EXECUTED",
            AuditLogModel.entity_id == rem_id,
        ).one()
        assert repair_log.username == "admin"
        assert repair_log.details["result"] == "RESOLVED"
        assert repair_log.details["affected_metrics"]["decay_percent"] == 0.0
    finally:
        db.close()

    # All state-derived API views must now agree.
    paths = client.get("/api/v1/paths", headers=headers).json()
    assert all(path["path_id"] != "path-003" for path in paths)
    assets = client.get("/api/v1/assets", headers=headers).json()
    assert all(asset["asset_id"] != "asset-003" for asset in assets)
    drift_after_repair = client.post("/api/v1/detect", headers=headers).json()
    assert drift_after_repair["total_changes"] == 0
    decay_after_repair = client.get("/api/v1/decay", headers=headers).json()
    assert decay_after_repair["decay_percent"] == 0.0
    assert decay_after_repair["health_label"] == "HEALTHY"

    # Simulate a process restart: subsequent reads must reconstruct state from DB.
    previous_engine_state = dict(engine_state)
    try:
        engine_state.update({
            "baseline_graph": None,
            "current_graph": None,
            "assumptions": [],
            "properties": [],
            "analyzed_changes": [],
            "latest_decay": None,
        })
        assert client.get("/api/v1/baseline", headers=headers).json()["is_active"] is True
        assert client.post("/api/v1/detect", headers=headers).json()["total_changes"] == 0
    finally:
        engine_state.update(previous_engine_state)


def test_failed_repair_rolls_back_state_and_audit(monkeypatch):
    token = create_access_token({"sub": "admin"})
    headers = {"Authorization": "Bearer " + token}
    client.post("/api/v1/baseline", json={"source": "demo"}, headers=headers)
    client.post("/api/v1/current", json={"source": "demo_drift"}, headers=headers)
    client.post("/api/v1/detect", headers=headers)
    repairs_response = client.get("/api/v1/repairs", headers=headers)
    assert repairs_response.status_code == 200, repairs_response.text
    repairs = repairs_response.json()
    candidate = repairs["recommended_repair"]
    remediation = client.post(
        "/api/v1/remediations",
        json={
            "repair_id": candidate["repair_id"],
            "description": candidate["description"],
            "action_type": candidate["action_type"],
            "target_entity": "path-003",
        },
        headers=headers,
    ).json()

    db = SessionLocal()
    try:
        before = db.get(GraphSnapshotModel, "current").graph_data
    finally:
        db.close()

    def fail_snapshot_write(*args, **kwargs):
        raise RuntimeError("injected persistence failure")

    monkeypatch.setattr("secureshadow.api.routes.persist_graph_snapshot", fail_snapshot_write)
    with pytest.raises(RuntimeError, match="injected persistence failure"):
        client.post(
            f"/api/v1/remediations/{remediation['remediation_id']}/verify",
            headers=headers,
        )

    db = SessionLocal()
    try:
        after = db.get(GraphSnapshotModel, "current").graph_data
        stored_remediation = db.query(RemediationModel).filter(
            RemediationModel.remediation_id == remediation["remediation_id"]
        ).one()
        repair_audit_count = db.query(AuditLogModel).filter(
            AuditLogModel.action == "REPAIR_EXECUTED",
            AuditLogModel.entity_id == remediation["remediation_id"],
        ).count()
        assert after == before
        assert stored_remediation.status == "IN_PROGRESS"
        assert repair_audit_count == 0
    finally:
        db.close()
