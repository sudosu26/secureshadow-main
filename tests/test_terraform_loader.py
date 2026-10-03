"""
Tests for TerraformLoader: Ingesting real Terraform show -json output into SECURESHADOW.
"""

from pathlib import Path
import pytest
from secureshadow.loaders.terraform import TerraformLoader
from secureshadow.drift import DriftDetector, AssumptionAnalyzer
from secureshadow.decay import DecayCalculator
from secureshadow.repair import RepairOptimizer

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_terraform_loader_baseline_graph_construction():
    """Verify loading real Terraform JSON state into SecurityGraph."""
    baseline_file = FIXTURES_DIR / "terraform_baseline.json"
    loader = TerraformLoader()

    graph, assumptions, properties = loader.build_graph_from_json(baseline_file)

    stats = graph.get_graph_stats()
    # Nodes: WAF (control), SG alb (control), Public ALB (load_balancer asset),
    # SG app (control), App server (compute asset), SG db (control), Postgres (database asset),
    # and Public Internet (external asset)
    assert stats["total_nodes"] >= 7
    assert stats["node_types"]["asset"] >= 3
    assert stats["node_types"]["control"] >= 4

    # Verify WAF protects ALB
    waf_nodes = [n for n, d in graph.graph.nodes(data=True) if d.get("control_type") == "waf"]
    assert len(waf_nodes) == 1
    waf_id = waf_nodes[0]
    alb_nodes = [n for n, d in graph.graph.nodes(data=True) if d.get("asset_type") == "load_balancer"]
    assert len(alb_nodes) == 1
    alb_id = alb_nodes[0]
    assert graph.graph.has_edge(waf_id, alb_id)

    # Verify Paths:
    # 1. Internet -> ALB
    # 2. ALB -> App Server
    # 3. App Server -> Database
    db_nodes = [n for n, d in graph.graph.nodes(data=True) if d.get("asset_type") == "database"]
    assert len(db_nodes) == 1
    db_id = db_nodes[0]

    app_nodes = [n for n, d in graph.graph.nodes(data=True) if d.get("asset_type") == "compute"]
    assert len(app_nodes) == 1
    app_id = app_nodes[0]

    assert graph.graph.has_edge(alb_id, app_id)
    assert graph.graph.has_edge(app_id, db_id)

    # In baseline, there should be NO direct path from any analytics service to DB
    assert len(graph.find_paths_between(alb_id, db_id)) > 0


def test_terraform_drift_and_bypass_detection():
    """
    End-to-end verification of Terraform drift:
    1. Parse baseline Terraform JSON
    2. Parse drifted Terraform JSON (with uninspected analytics service talking directly to DB)
    3. Run DriftDetector -> flags new asset and new bypass communication path
    4. Run AssumptionAnalyzer -> flags database access assumption violation
    5. Run DecayCalculator -> computes decay score on IaC data
    6. Run RepairOptimizer -> generates remediation candidates
    """
    loader = TerraformLoader()
    baseline_file = FIXTURES_DIR / "terraform_baseline.json"
    drifted_file = FIXTURES_DIR / "terraform_drifted.json"

    baseline_graph, baseline_assumptions, baseline_props = loader.build_graph_from_json(baseline_file)
    drifted_graph, _, _ = loader.build_graph_from_json(drifted_file)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    # 1. Detect drift
    changes = detector.detect_drift(drifted_graph)
    assert len(changes) >= 2

    change_types = [c.change_type for c in changes]
    assert "new_asset" in change_types or "new_compute" in change_types
    assert "new_communication_path" in change_types

    # Find the bypass path change
    bypass_change = next(c for c in changes if c.change_type == "new_communication_path")
    assert "AI Analytics Service" in bypass_change.description
    assert bypass_change.severity == "critical"

    # 2. Analyze assumptions
    analyzer = AssumptionAnalyzer(baseline_assumptions)
    analyzed_changes = analyzer.analyze(changes)

    broken_changes = [c for c in analyzed_changes if c.potentially_breaks_assumptions]
    assert len(broken_changes) > 0

    # 3. Compute decay
    calculator = DecayCalculator()
    target_prop = next(p for p in baseline_props if "database" in p.description.lower() or "confidentiality" in p.description.lower())
    decay_result = calculator.calculate(target_prop, analyzed_changes)

    assert decay_result.decay_percent > 0.0
    assert decay_result.current_protection < 100.0

    # 4. Generate repairs
    optimizer = RepairOptimizer()
    candidates = optimizer.generate_candidates(decay_result, analyzed_changes, drifted_graph)
    assert len(candidates) > 0

    best = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)
    assert best is not None
    assert best.action_type in ["remove_path", "add_control"]
