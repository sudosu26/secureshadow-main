"""
Tests for closed-loop Remediation Tracking and Verification lifecycle.
"""

import pytest
from fastapi.testclient import TestClient
from secureshadow.api.app import app
from secureshadow.db.database import init_db, SessionLocal
from secureshadow.api.auth import seed_admin_user

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

    # 7. Confirm remediation is persisted as RESOLVED in DB
    res_rems_after = client.get("/api/v1/remediations", headers=headers)
    verified_item = next(r for r in res_rems_after.json() if r["remediation_id"] == rem_id)
    assert verified_item["status"] == "RESOLVED"
    assert verified_item["resolved_at"] is not None
