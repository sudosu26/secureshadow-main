"""
Tests for DriftDetector and AssumptionAnalyzer.
"""

import pytest
from secureshadow.models import Asset, SecurityControl, Assumption, CommunicationPath
from secureshadow.graph import SecurityGraph
from secureshadow.drift import DriftDetector, AssumptionAnalyzer
from secureshadow.scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario


def test_baseline_capture():
    """Verify baseline snapshot properly captures nodes and edges."""
    scenario = create_demo_scenario()
    graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(graph)

    assert detector.baseline_snapshot is not None
    assert len(detector.baseline_snapshot["nodes"]) == 5  # asset-001, asset-002, asset-ext, ctrl-001, asm-001
    assert len(detector.baseline_snapshot["edges"]) == 5


def test_no_drift_when_graphs_identical():
    """Verify no changes detected when comparing graph with itself."""
    scenario = create_demo_scenario()
    graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(graph)

    changes = detector.detect_drift(graph)
    assert len(changes) == 0


def test_drift_detection_new_asset_and_bypass_path():
    """Verify detection of newly introduced unreviewed service and bypass route."""
    scenario = create_demo_scenario()
    baseline_graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    drifted = create_drifted_scenario(scenario)
    current_graph = drifted["current_graph"]

    changes = detector.detect_drift(current_graph)
    assert len(changes) == 2

    change_types = {c.change_type for c in changes}
    assert "new_asset" in change_types
    assert "new_communication_path" in change_types

    # Find the communication path change
    path_change = next(c for c in changes if c.change_type == "new_communication_path")
    assert path_change.severity == "critical"
    assert "asset-003" in path_change.affected_entities
    assert "asset-002" in path_change.affected_entities


def test_assumption_analyzer_flags_violation():
    """Verify AssumptionAnalyzer flags the bypass path as breaking asm-001."""
    scenario = create_demo_scenario()
    baseline_graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    drifted = create_drifted_scenario(scenario)
    changes = detector.detect_drift(drifted["current_graph"])

    analyzer = AssumptionAnalyzer(scenario["assumptions"])
    analyzed_changes = analyzer.analyze(changes, current_graph=drifted["current_graph"], baseline_graph=baseline_graph)

    # Both new asset and new communication path trigger assumption review because AI service connects directly to DB
    broken_changes = [c for c in analyzed_changes if c.potentially_breaks_assumptions]
    assert len(broken_changes) == 2

    for c in broken_changes:
        assert c.affected_assumption_id == "asm-001"
        assert c.severity == "critical"


def test_unrelated_asset_does_not_flag_assumption():
    """
    Verify topology-aware analysis: an unrelated asset in a disconnected subnet
    does NOT break assumptions protecting the Customer API/DB enclave.
    The old coarse analyzer would have incorrectly flagged asm-001.
    """
    scenario = create_demo_scenario()
    baseline_graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    # Clone baseline graph into drifted state and add unrelated assets in isolated subnet
    drifted_graph = build_baseline_graph(scenario)
    printer = Asset("asset-printer", "Office Printer", "hardware", "192.168.10.50")
    workstation = Asset("asset-laptop", "Staff Laptop", "workstation", "192.168.10.20")
    printer_path = CommunicationPath("path-print-001", workstation, printer, "IPP")

    drifted_graph.add_asset(printer)
    drifted_graph.add_asset(workstation)
    drifted_graph.add_path(printer_path)

    changes = detector.detect_drift(drifted_graph)
    assert len(changes) >= 2  # New assets and path detected

    analyzer = AssumptionAnalyzer(scenario["assumptions"])
    analyzed_changes = analyzer.analyze(changes, current_graph=drifted_graph, baseline_graph=baseline_graph)

    # Unrelated changes must NOT break asm-001
    broken_changes = [c for c in analyzed_changes if c.potentially_breaks_assumptions]
    assert len(broken_changes) == 0, (
        f"Expected 0 assumption violations for unrelated assets, but found: {broken_changes}"
    )


def test_removed_control_and_removed_path():
    """Verify removal of a control or communication path is properly reported."""
    scenario = create_demo_scenario()
    baseline_graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    # Create modified graph with control removed
    modified_graph = SecurityGraph()
    for a in scenario["assets"]:
        modified_graph.add_asset(a)

    changes = detector.detect_drift(modified_graph)
    change_types = {c.change_type for c in changes}

    assert "removed_control" in change_types
    assert "removed_path" in change_types
