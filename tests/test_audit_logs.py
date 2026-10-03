"""
Tests for Audit Log persistence and querying.
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


def test_audit_logs_recorded_during_pipeline():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Capture baseline
    res_b = client.post("/api/v1/baseline", json={"source": "demo"}, headers=headers)
    assert res_b.status_code == 200

    # 2. Check audit logs contain BASELINE_CAPTURED
    res_logs = client.get("/api/v1/audit-logs", headers=headers)
    assert res_logs.status_code == 200
    logs = res_logs.json()
    actions = [l["action"] for l in logs]
    assert "BASELINE_CAPTURED" in actions
    assert "USER_LOGIN" in actions

    # 3. Submit current drift & detect
    client.post("/api/v1/current", json={"source": "demo_drift"}, headers=headers)
    client.post("/api/v1/detect", headers=headers)

    res_logs2 = client.get("/api/v1/audit-logs", headers=headers)
    actions2 = [l["action"] for l in res_logs2.json()]
    assert "CURRENT_STATE_SUBMITTED" in actions2
    assert "DRIFT_DETECTED" in actions2
