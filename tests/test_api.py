"""
Integration tests for SECURESHADOW FastAPI service and PostgreSQL/SQLAlchemy persistence.
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


def get_auth_token():
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secureshadowadmin"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_auth_login_success_and_failure():
    # Success
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secureshadowadmin"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Bad password
    res_bad = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert res_bad.status_code == 401


def test_unauthorized_access_blocked():
    res = client.get("/api/v1/baseline")
    assert res.status_code == 401


def test_end_to_end_api_lifecycle():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Capture baseline
    res_b = client.post("/api/v1/baseline", json={"source": "demo"}, headers=headers)
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert data_b["status"] == "baseline_established"
    assert data_b["total_nodes"] == 5

    # 2. Get baseline
    res_gb = client.get("/api/v1/baseline", headers=headers)
    assert res_gb.status_code == 200
    assert res_gb.json()["is_active"] is True

    # 3. Submit current drift state
    res_c = client.post("/api/v1/current", json={"source": "demo_drift"}, headers=headers)
    assert res_c.status_code == 200
    assert res_c.json()["status"] == "current_state_recorded"

    # 4. Trigger drift detection
    res_d = client.post("/api/v1/detect", headers=headers)
    assert res_d.status_code == 200
    data_d = res_d.json()
    assert data_d["total_changes"] == 2
    assert data_d["critical_count"] == 2

    # 5. Compute decay score
    res_decay = client.get("/api/v1/decay", headers=headers)
    assert res_decay.status_code == 200
    data_decay = res_decay.json()
    assert data_decay["decay_percent"] == 52.5
    assert data_decay["current_protection"] == 47.5
    assert data_decay["health_label"] == "AT RISK"
    assert len(data_decay["contributors"]) == 2

    # 6. Get repair recommendations
    res_r = client.get("/api/v1/repairs?min_improvement=50.0", headers=headers)
    assert res_r.status_code == 200
    data_r = res_r.json()
    assert data_r["total_candidates"] == 6
    rec = data_r["recommended_repair"]
    assert rec is not None
    assert rec["action_type"] == "remove_path"
    assert rec["total_cost"] == pytest.approx(23.0, 0.01)
    assert rec["security_improvement"] == 100.0

    # 7. Check persistence in Assets & Controls endpoints
    res_assets = client.get("/api/v1/assets", headers=headers)
    assert res_assets.status_code == 200
    assert len(res_assets.json()) >= 2
    customer_api = next(asset for asset in res_assets.json() if asset["asset_id"] == "asset-001")
    assert "Web Application Firewall" in customer_api["protecting_controls"]

    res_ctrls = client.get("/api/v1/controls", headers=headers)
    assert res_ctrls.status_code == 200
    assert len(res_ctrls.json()) >= 1
    waf = next(control for control in res_ctrls.json() if control["control_id"] == "ctrl-001")
    assert "Customer API" in waf["protects"]


def test_change_password_flow():
    """Verify authenticated password rotation works and old credentials are invalidated."""
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Reject bad current password
    res_bad_curr = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "wrong_current_password", "new_password": "newsecretpassword123"},
        headers=headers,
    )
    assert res_bad_curr.status_code == 400

    # 2. Reject short password
    res_short = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "secureshadowadmin", "new_password": "short"},
        headers=headers,
    )
    assert res_short.status_code == 400

    # 3. Successful rotation
    res_ok = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "secureshadowadmin", "new_password": "newsecretpassword123"},
        headers=headers,
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["status"] == "success"

    # 4. Old password rejected
    res_old = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secureshadowadmin"})
    assert res_old.status_code == 401

    # 5. New password accepted
    res_new = client.post("/api/v1/auth/login", json={"username": "admin", "password": "newsecretpassword123"})
    assert res_new.status_code == 200
    new_token = res_new.json()["access_token"]

    # 6. Revert password back for other tests
    client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "newsecretpassword123", "new_password": "secureshadowadmin"},
        headers={"Authorization": f"Bearer {new_token}"},
    )
