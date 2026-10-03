"""
Tests for DecayCalculator and DecayResult.
"""

import pytest
from secureshadow.models import SecurityProperty, Assumption
from secureshadow.drift import DriftDetector, AssumptionAnalyzer, ChangeEvent
from secureshadow.decay import DecayCalculator, DecayResult, DecayContributor
from secureshadow.scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario


def test_decay_calculation_known_good_scenario():
    """
    Assert exact mathematical values against the canonical demo scenario:
    - Base weight new_communication_path: 25.0 * 1.5 (critical) = 37.5%
    - Base weight new_asset: 10.0 * 1.5 (critical) = 15.0%
    - Total decay: 52.5%
    - Current protection: 47.5%
    - Health label: AT RISK
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
    property_to_test = scenario["properties"][0]

    decay_result = calculator.calculate(property_to_test, analyzed_changes)

    assert decay_result.baseline_protection == 100.0
    assert decay_result.decay_percent == 52.5
    assert decay_result.current_protection == 47.5
    assert decay_result.get_health_label() == "AT RISK"
    assert len(decay_result.contributors) == 2
    assert "asm-001" in decay_result.broken_assumptions

    # Check individual contributor impact
    path_contrib = next(c for c in decay_result.contributors if "data flow" in c.change_desc.lower())
    assert path_contrib.impact_percent == 37.5

    asset_contrib = next(c for c in decay_result.contributors if "asset" in c.change_desc.lower())
    assert asset_contrib.impact_percent == 15.0


def test_decay_cap_at_fifty_percent():
    """Verify individual impact is capped at 50% even with high multiplier."""
    calculator = DecayCalculator()
    prop = SecurityProperty("prop-test", "High risk asset", "ctrl-1", severity="critical")
    asm = Assumption("asm-test", "Strict isolation", "ctrl-1")
    prop.add_assumption(asm)

    # Change with high base weight (e.g. removed_control: 30 * 1.5 = 45; if 40 * 1.5 = 60, capped at 50)
    change = ChangeEvent("removed_control", "Control eliminated", ["ctrl-1"], severity="critical")
    change.potentially_breaks_assumptions = True
    change.affected_assumption_id = "asm-test"
    change.affected_assumption_desc = "Strict isolation"

    # Set custom high weight test
    calculator.IMPACT_WEIGHTS["custom_super_high"] = 50.0
    change.change_type = "custom_super_high"

    result = calculator.calculate(prop, [change])
    assert result.contributors[0].impact_percent == 50.0
    assert result.decay_percent == 50.0
    assert result.current_protection == 50.0


def test_zero_decay_when_no_broken_assumptions():
    """Verify decay is 0.0% when changes do not break assumptions."""
    scenario = create_demo_scenario()
    calculator = DecayCalculator()
    property_to_test = scenario["properties"][0]

    change = ChangeEvent("new_documentation", "Docs added", ["doc-1"], severity="info")
    result = calculator.calculate(property_to_test, [change])

    assert result.decay_percent == 0.0
    assert result.current_protection == 100.0
    assert result.get_health_label() == "HEALTHY"
    assert len(result.contributors) == 0


def test_decay_health_label_thresholds():
    """Verify categorical health labels at each boundary."""
    result = DecayResult("prop-01", "Test")

    result.current_protection = 95.0
    assert result.get_health_label() == "HEALTHY"

    result.current_protection = 75.0
    assert result.get_health_label() == "DEGRADED"

    result.current_protection = 45.0
    assert result.get_health_label() == "AT RISK"

    result.current_protection = 20.0
    assert result.get_health_label() == "CRITICAL"
