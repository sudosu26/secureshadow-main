"""
SECURESHADOW - Command Line Interface (CLI) Entrypoint
Dedicated user-facing CLI presentation layer for running demo scenarios
and analyzing real Terraform infrastructure data.
"""

import sys
import argparse
from datetime import datetime
from typing import Optional, List

# Ensure safe output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from secureshadow.models import Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath
from secureshadow.graph import SecurityGraph
from secureshadow.drift import DriftDetector, AssumptionAnalyzer, ChangeEvent
from secureshadow.decay import DecayCalculator, DecayResult
from secureshadow.repair import RepairOptimizer, RepairCandidate
from secureshadow.scenarios import create_demo_scenario, build_baseline_graph, create_drifted_scenario
from secureshadow.loaders.terraform import TerraformLoader


def print_banner():
    print("=" * 60)
    print("  SECURESHADOW - Security Shadow Protection System")
    print("  Detecting Silently Degraded Security Controls")
    print("=" * 60)
    print()


def run_demo_cli(interactive: bool = False):
    """Run the complete reference pipeline in the terminal."""
    print_banner()
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Scenario: WAF protecting Customer API -> Customer Database\n")

    # 1. Baseline
    print("┌─ [1] BASELINE ARCHITECTURE")
    baseline_data = create_demo_scenario()
    baseline_graph = build_baseline_graph(baseline_data)
    detector = DriftDetector()
    detector.set_baseline(baseline_graph)

    stats = baseline_graph.get_graph_stats()
    print(f"│ Total Nodes: {stats['total_nodes']} | Edges: {stats['total_edges']}")
    print("│ Path: Internet -> [WAF] -> Customer API -> Customer DB (Protected)")
    print("└─────────────────────────────────────────────────────────\n")

    # 2. Drift
    print("┌─ [2] INTRODUCING ARCHITECTURAL DRIFT")
    drifted = create_drifted_scenario(baseline_data)
    current_graph = drifted["current_graph"]
    print(f"│ Added Asset: '{drifted['new_asset'].name}' ({drifted['new_asset'].asset_type})")
    print(f"│ Added Path:  {drifted['new_asset'].name} -> {baseline_data['assets'][1].name}")
    print("│ Notice: Path bypasses the Web Application Firewall!")
    print("└─────────────────────────────────────────────────────────\n")

    # 3. Detection
    print("┌─ [3] DRIFT DETECTION")
    changes = detector.detect_drift(current_graph)
    print(f"│ Changes detected: {len(changes)}")
    for c in changes:
        print(f"│ [{c.severity.upper()}] {c.change_type}: {c.description}")
    print("└─────────────────────────────────────────────────────────\n")

    # 4. Assumption Analysis
    print("┌─ [4] ASSUMPTION ANALYSIS")
    analyzer = AssumptionAnalyzer(baseline_data["assumptions"])
    analyzed_changes = analyzer.analyze(changes, current_graph=current_graph, baseline_graph=baseline_graph)
    for asm in baseline_data["assumptions"]:
        violating = [c for c in analyzed_changes if getattr(c, "affected_assumption_id", None) == asm.assumption_id]
        if violating:
            print(f"│ [VIOLATED] Assumption {asm.assumption_id}: {asm.description}")
            for v in violating:
                print(f"│   Trigger: {v.description}")
        else:
            print(f"│ [VALID] Assumption {asm.assumption_id}: {asm.description}")
    print("└─────────────────────────────────────────────────────────\n")

    # 5. Protection Decay Score
    print("┌─ [5] PROTECTION DECAY CALCULATION")
    calculator = DecayCalculator()
    target_prop = baseline_data["properties"][0]
    decay_result = calculator.calculate(target_prop, analyzed_changes)

    print(f"│ Security Property:   {decay_result.property_desc}")
    print(f"│ Baseline Protection: {decay_result.baseline_protection:.0f}%")
    print(f"│ Current Protection:  {decay_result.current_protection:.0f}%")
    print(f"│ Protection Decay:    -{decay_result.decay_percent:.0f}%")
    print(f"│ Status:              {decay_result.get_health_label()}")
    if decay_result.contributors:
        print("│ Attribution Breakdown:")
        for c in decay_result.contributors:
            print(f"│   -{c.impact_percent:.1f}%: {c.change_desc}")
            print(f"│           Broken assumption: {c.assumption_desc}")
    print("└─────────────────────────────────────────────────────────\n")

    # 6. Minimum-Cost Repair Recommendation
    print("┌─ [6] MINIMUM-COST REPAIR SELECTION")
    optimizer = RepairOptimizer()
    candidates = optimizer.generate_candidates(decay_result, analyzed_changes, current_graph)
    best_repair = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)

    if best_repair:
        print(f"│ [RECOMMENDED] {best_repair.description}")
        print(f"│ Action Type:          {best_repair.action_type.replace('_', ' ').title()}")
        print(f"│ Total Cost Score:     {best_repair.total_cost:.1f} / 100 (Lower is cheaper)")
        print(f"│ Security Restoration: +{best_repair.security_improvement:.0f}%")
        print(f"│ Restored Assumptions: {best_repair.restored_assumptions}")
        print("│ Cost Factor Breakdown:")
        print(f"│   Implementation Cost: {best_repair.implementation_cost}/100")
        print(f"│   Business Impact:     {best_repair.business_impact}/100")
        print(f"│   Operational Risk:    {best_repair.operational_risk}/100")
        print(f"│   Implementation Time: {best_repair.implementation_time}/100")
    print("└─────────────────────────────────────────────────────────\n")

    # Summary comparison
    print("=" * 60)
    print("VERDICT: Control remains active, but security guarantee decayed.")
    print(f"Recommended action restores protection to: {min(100.0, decay_result.current_protection + (best_repair.security_improvement if best_repair else 0)):.0f}%")
    print("=" * 60)

    if interactive:
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass


def run_terraform_cli(baseline_path: str, current_path: Optional[str] = None):
    """Analyze real Terraform show -json files."""
    print_banner()
    loader = TerraformLoader()

    print(f"Loading baseline Terraform configuration from: {baseline_path}")
    base_graph, base_asms, base_props = loader.build_graph_from_json(baseline_path)
    base_stats = base_graph.get_graph_stats()
    print(f"Baseline parsed: {base_stats['total_nodes']} nodes, {base_stats['total_edges']} edges.\n")

    if not current_path:
        print("No current state supplied. Baseline graph successfully constructed.")
        return

    print(f"Loading current/drifted Terraform configuration from: {current_path}")
    curr_graph, _, _ = loader.build_graph_from_json(current_path)
    curr_stats = curr_graph.get_graph_stats()
    print(f"Current parsed: {curr_stats['total_nodes']} nodes, {curr_stats['total_edges']} edges.\n")

    detector = DriftDetector()
    detector.set_baseline(base_graph)
    changes = detector.detect_drift(curr_graph)

    print(f"Detected {len(changes)} architectural change(s):")
    for c in changes:
        print(f"  [{c.severity.upper()}] {c.change_type}: {c.description}")
    print()

    analyzer = AssumptionAnalyzer(base_asms)
    analyzed = analyzer.analyze(changes, current_graph=curr_graph, baseline_graph=base_graph)

    calculator = DecayCalculator()
    optimizer = RepairOptimizer()

    for prop in base_props:
        res = calculator.calculate(prop, analyzed)
        print(f"Property: {prop.description}")
        print(f"  Current Protection: {res.current_protection:.0f}% (Decay: -{res.decay_percent:.0f}%) [{res.get_health_label()}]")
        if res.decay_percent > 0:
            candidates = optimizer.generate_candidates(res, analyzed, curr_graph)
            best = optimizer.find_minimum_cost_repair(min_security_improvement=50.0)
            if best:
                print(f"  Recommended Repair: {best.description} (Cost: {best.total_cost:.1f}, Restores: +{best.security_improvement:.0f}%)")
        print()


def main():
    parser = argparse.ArgumentParser(description="SECURESHADOW Security Control Decay Detection Engine")
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="Run the reference scenario demo")
    demo_parser.add_argument("--interactive", action="store_true", help="Prompt before exiting")

    tf_parser = subparsers.add_parser("terraform", help="Analyze Terraform show -json infrastructure")
    tf_parser.add_argument("baseline", help="Path to baseline terraform show -json file")
    tf_parser.add_argument("--current", help="Path to current/drifted terraform show -json file", default=None)

    args = parser.parse_args()

    if args.command == "terraform":
        run_terraform_cli(args.baseline, args.current)
    else:
        # Default to demo if no command specified
        run_demo_cli(interactive=getattr(args, "interactive", False))


if __name__ == "__main__":
    main()
