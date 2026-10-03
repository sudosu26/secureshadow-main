"""
SECURESHADOW - Reference Scenarios
Provides deterministic reference scenarios for testing and demonstration.
Contains pure data structures with zero console side-effects.
"""

from typing import Dict, List, Any
from .models import Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath
from .graph import SecurityGraph


def create_demo_scenario() -> Dict[str, Any]:
    """
    Builds the known-good enterprise demo scenario:
    - Customer API (asset-001)
    - Customer Database (asset-002)
    - WAF (ctrl-001) protecting Customer API
    - Assumption (asm-001) that all external HTTP traffic passes through WAF
    - Security Property (prop-001) protecting customer PII data (critical severity)
    - Paths: Internet -> Customer API (passes WAF), Customer API -> Customer DB
    """
    customer_api = Asset("asset-001", "Customer API", "api", "10.0.1.5")
    customer_db = Asset("asset-002", "Customer Database", "database", "10.0.2.10")
    internet = Asset("asset-ext", "Internet", "external")

    waf = SecurityControl("ctrl-001", "Web Application Firewall", "waf", "active")
    waf.add_protected_asset(customer_api)

    all_traffic_through_waf = Assumption(
        "asm-001",
        "All external HTTP traffic to Customer API must pass through the WAF",
        "ctrl-001",
    )

    protect_customer_data = SecurityProperty(
        "prop-001",
        "Only authenticated and authorized users can access customer PII data",
        "ctrl-001",
        severity="critical",
    )
    protect_customer_data.add_assumption(all_traffic_through_waf)

    internet_to_api = CommunicationPath("path-001", internet, customer_api, "HTTPS")
    internet_to_api.add_control(waf)

    api_to_db = CommunicationPath("path-002", customer_api, customer_db, "TCP")

    return {
        "assets": [customer_api, customer_db, internet],
        "controls": [waf],
        "assumptions": [all_traffic_through_waf],
        "properties": [protect_customer_data],
        "paths": [internet_to_api, api_to_db],
    }


def build_baseline_graph(scenario: Dict[str, Any]) -> SecurityGraph:
    """Helper to populate a SecurityGraph from scenario dictionary."""
    graph = SecurityGraph()
    for asset in scenario["assets"]:
        graph.add_asset(asset)
    for control in scenario["controls"]:
        graph.add_control(control)
    for assumption in scenario["assumptions"]:
        graph.add_assumption(assumption)
    for path in scenario["paths"]:
        graph.add_path(path)
    return graph


def create_drifted_scenario(baseline_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Introduces the unreviewed AI Analytics Service bypassing the WAF.
    """
    ai_service = Asset("asset-003", "AI Analytics Service", "service", "10.0.3.20")
    bypass_path = CommunicationPath("path-003", ai_service, baseline_data["assets"][1], "HTTPS")

    current_graph = SecurityGraph()
    for asset in baseline_data["assets"]:
        current_graph.add_asset(asset)
    current_graph.add_asset(ai_service)

    for control in baseline_data["controls"]:
        current_graph.add_control(control)
    for assumption in baseline_data["assumptions"]:
        current_graph.add_assumption(assumption)
    for path in baseline_data["paths"]:
        current_graph.add_path(path)
    current_graph.add_path(bypass_path)

    return {
        "current_graph": current_graph,
        "new_asset": ai_service,
        "bypass_path": bypass_path,
    }
