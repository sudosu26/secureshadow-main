"""
Tests for RepairOptimizer and RepairCandidate ranking.
"""

import pytest
from secureshadow.drift import DriftDetector, AssumptionAnalyzer
from secureshadow.decay import DecayCalculator
from secureshadow.repair import RepairOptimizer, RepairCandidate
from secureshadow.scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario


def test_repair_generation_and_exact_cost_math():
    """
    Assert exact cost formula for each candidate in the demo scenario:
    Formula: 0.35 * cost + 0.30 * impact + 0.25 * risk + 0.10 * time
    """
    scenario = create_demo_scenario()
    baseline_graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    drifted = create_drifted_scenario(scenario)
    changes = detector.detect_drift(drifted["current_graph"])

    analyzer = AssumptionAnalyzer(scenario["assumptions"])
    analyzed_changes = analyzer.analyze(changes)

    calculator = DecayCalculator()
    decay_result = calculator.calculate(scenario["properties"][0], analyzed_changes)

    optimizer = RepairOptimizer()
    candidates = optimizer.generate_candidates(decay_result, analyzed_changes, drifted["current_graph"])

    # 4 options for path + 1 for asset + 1 for accept_risk = 6 candidates
    assert len(candidates) == 6

    # Test candidate: remove_path
    remove_c = next(c for c in candidates if c.action_type == "remove_path")
    expected_remove_cost = 20 * 0.35 + 40 * 0.30 + 10 * 0.25 + 15 * 0.10  # 7 + 12 + 2.5 + 1.5 = 23.0
    assert remove_c.total_cost == pytest.approx(expected_remove_cost, 0.01)
    assert remove_c.security_improvement == 100.0

    # Test candidate: accept_risk
    accept_c = next(c for c in candidates if c.action_type == "accept_risk")
    expected_accept_cost = 0 + 0 + 80 * 0.25 + 0  # 20.0
    assert accept_c.total_cost == pytest.approx(expected_accept_cost, 0.01)
    assert accept_c.security_improvement == 0.0

    # Test candidate: add_encryption
    enc_c = next(c for c in candidates if c.action_type == "add_encryption")
    expected_enc_cost = 25 * 0.35 + 10 * 0.30 + 10 * 0.25 + 20 * 0.10  # 8.75 + 3 + 2.5 + 2 = 16.25
    assert enc_c.total_cost == pytest.approx(expected_enc_cost, 0.01)
    assert enc_c.security_improvement == 45.0


def test_minimum_cost_repair_selection():
    """
    Verify find_minimum_cost_repair(min_security_improvement=50.0) selects
    remove_path as the optimal candidate.
    """
    scenario = create_demo_scenario()
    baseline_graph = build_baseline_graph(scenario)

    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    drifted = create_drifted_scenario(scenario)
    changes = detector.detect_drift(drifted["current_graph"])

    analyzer = AssumptionAnalyzer(scenario["assumptions"])
    analyzed_changes = analyzer.analyze(changes)

    calculator = DecayCalculator()
    decay_result = calculator.calculate(scenario["properties"][0], analyzed_changes)

    optimizer = RepairOptimizer()
    optimizer.generate_candidates(decay_result, analyzed_changes)

    best_repair = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)

    assert best_repair is not None
    assert best_repair.action_type == "remove_path"
    assert best_repair.total_cost == pytest.approx(23.0, 0.01)
    assert best_repair.security_improvement == 100.0
    assert "asm-001" in best_repair.restored_assumptions


def test_minimum_cost_repair_threshold_filtering():
    """Verify that candidates below the security improvement threshold are excluded."""
    optimizer = RepairOptimizer()

    cheap_but_weak = RepairCandidate("R1", "Weak patch", "patch")
    cheap_but_weak.implementation_cost = 5.0
    cheap_but_weak.security_improvement = 30.0
    cheap_but_weak.calculate_total_cost()

    expensive_effective = RepairCandidate("R2", "Full overhaul", "overhaul")
    expensive_effective.implementation_cost = 50.0
    expensive_effective.security_improvement = 90.0
    expensive_effective.calculate_total_cost()

    optimizer.candidates = [cheap_but_weak, expensive_effective]

    # With threshold 50.0, cheap_but_weak must be excluded
    best = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)
    assert best.repair_id == "R2"

    # With threshold 95.0, no candidates qualify
    none_best = optimizer.find_minimum_cost_repair(min_security_improvement=95.0)
    assert none_best is None
