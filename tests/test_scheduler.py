"""
Tests for APScheduler background re-detection job.
"""

import pytest
from secureshadow.api.scheduler import scheduled_detection_job
from secureshadow.scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario
from secureshadow.api.routes import engine_state
from secureshadow.db.database import init_db


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

    # Execute the scheduled job directly
    await scheduled_detection_job()

    # Verify detection and decay ran
    assert len(engine_state["analyzed_changes"]) == 2
    assert engine_state["latest_decay"] is not None
    assert engine_state["latest_decay"].decay_percent == 52.5
