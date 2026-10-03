"""
Tests for Inventory CRUD operations (Assets, Controls, Paths).
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


def test_asset_crud():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create asset
    res_c = client.post(
        "/api/v1/assets",
        json={"asset_id": "test-asset-99", "name": "Payment Service", "asset_type": "service", "ip_address": "10.0.9.9"},
        headers=headers,
    )
    assert res_c.status_code == 200
    assert res_c.json()["asset_id"] == "test-asset-99"

    # List assets
    res_l = client.get("/api/v1/assets", headers=headers)
    assert any(a["asset_id"] == "test-asset-99" for a in res_l.json())

    # Delete asset
    res_d = client.delete("/api/v1/assets/test-asset-99", headers=headers)
    assert res_d.status_code == 200
    assert res_d.json()["status"] == "deleted"


def test_control_and_path_crud():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}

    # Create control
    res_ctrl = client.post(
        "/api/v1/controls",
        json={"control_id": "test-ctrl-99", "name": "Cloudflare WAF", "control_type": "waf", "status": "active"},
        headers=headers,
    )
    assert res_ctrl.status_code == 200

    # Create path
    res_path = client.post(
        "/api/v1/paths",
        json={"path_id": "test-path-99", "source_id": "asset-001", "destination_id": "asset-002", "protocol": "HTTPS"},
        headers=headers,
    )
    assert res_path.status_code == 200

    # Delete path
    res_del_path = client.delete("/api/v1/paths/test-path-99", headers=headers)
    assert res_del_path.status_code == 200

    # Delete control
    res_del_ctrl = client.delete("/api/v1/controls/test-ctrl-99", headers=headers)
    assert res_del_ctrl.status_code == 200
