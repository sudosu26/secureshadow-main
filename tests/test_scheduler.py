"""
Tests for APScheduler background re-detection job.
"""

import pytest
from secureshadow.api.scheduler import scheduled_detection_job
from secureshadow.scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario
from secureshadow.api.routes import engine_state
from secureshadow.db.database import init_db, SessionLocal
from secureshadow.db.models import GraphSnapshotModel
from secureshadow.services.graph_state import persist_graph_snapshot, persist_security_definitions


def persist_scenario(scenario, baseline_graph, current_graph):
    db = SessionLocal()
    try:
        db.query(GraphSnapshotModel).delete()
        persist_graph_snapshot(db, "baseline", baseline_graph)
        persist_graph_snapshot(db, "current", current_graph)
        persist_security_definitions(db, scenario["assumptions"], scenario["properties"])
        db.commit()
    finally:
        db.close()


@pytest.mark.anyio
async def test_scheduled_detection_job_execution():
    init_db()
    # Setup baseline and drift in engine_state
    scenario = create_demo_scenario()
    engine_state["baseline_graph"] = build_baseline_graph(scenario)
    engine_state["assumptions"] = scenario["assumptions"]
    engine_state["properties"] = scenario["properties"]

    drifted = create_drifted_scenario(scenario)
    engine_state["current_graph"] = drifted["current_graph"]
    persist_scenario(
        scenario,
        engine_state["baseline_graph"],
        engine_state["current_graph"],
    )

    # Execute the scheduled job directly
    await scheduled_detection_job()

    # Verify detection and decay ran
    assert len(engine_state["analyzed_changes"]) == 2
    assert engine_state["latest_decay"] is not None
    assert engine_state["latest_decay"].decay_percent == 52.5


@pytest.mark.anyio
async def test_scheduled_job_logs_failure_on_missing_terraform_plan(monkeypatch, caplog):
    import logging
    init_db()
    scenario = create_demo_scenario()
    engine_state["baseline_graph"] = build_baseline_graph(scenario)
    persist_scenario(
        scenario,
        engine_state["baseline_graph"],
        engine_state["baseline_graph"],
    )

    # Point to nonexistent plan file
    monkeypatch.setenv("SCHEDULED_TERRAFORM_PLAN_PATH", "nonexistent/plan/file.json")

    with caplog.at_level(logging.ERROR):
        await scheduled_detection_job()

    assert any("Configured SCHEDULED_TERRAFORM_PLAN_PATH not found" in record.message for record in caplog.records)
    assert any("Scheduler error during scan" in record.message for record in caplog.records)
