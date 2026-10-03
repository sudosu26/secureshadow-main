"""
SECURESHADOW - Drift Detection Engine
Detects architectural changes between baseline and current graph snapshots,
and determines if any changes potentially invalidate security assumptions.
"""

from datetime import datetime
import logging
from typing import Dict, List, Optional, Any

from .models import Assumption
from .graph import SecurityGraph

logger = logging.getLogger(__name__)


class ChangeEvent:
    """
    Represents an atomic structural difference detected between baseline and current states.
    """
    def __init__(
        self,
        change_type: str,
        description: str,
        affected_entities: List[str],
        severity: str = "info",
    ):
        self.change_type = change_type      # e.g., "new_asset", "new_communication_path", "removed_control"
        self.description = description
        self.affected_entities = affected_entities
        self.severity = severity            # "info", "warning", "critical"
        self.timestamp = datetime.now()
        self.potentially_breaks_assumptions: bool = False
        self.affected_assumption_id: Optional[str] = None
        self.affected_assumption_desc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_type": self.change_type,
            "description": self.description,
            "affected_entities": self.affected_entities,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "potentially_breaks_assumptions": self.potentially_breaks_assumptions,
            "affected_assumption_id": self.affected_assumption_id,
            "affected_assumption_desc": self.affected_assumption_desc,
        }

    def __repr__(self) -> str:
        return f"[{self.severity.upper()}] {self.change_type}: {self.description}"


class DriftDetector:
    """
    Compares a baseline SecurityGraph snapshot against a current SecurityGraph
    to produce structured ChangeEvents.
    """

    def __init__(self):
        self.baseline_graph: Optional[SecurityGraph] = None
        self.baseline_snapshot: Optional[Dict[str, Any]] = None

    def set_baseline(self, graph: SecurityGraph) -> None:
        """
        Record the current state of the graph as the known-good baseline.
        """
        self.baseline_graph = graph
        self.baseline_snapshot = self._snapshot(graph)
        logger.debug(
            "Baseline recorded with %d nodes and %d edges",
            len(self.baseline_snapshot["nodes"]),
            len(self.baseline_snapshot["edges"]),
        )

    def detect_drift(self, current_graph: SecurityGraph) -> List[ChangeEvent]:
        """
        Compare current graph against the recorded baseline snapshot.
        """
        if self.baseline_snapshot is None:
            raise ValueError("Baseline not set. Call set_baseline() first.")

        current_snapshot = self._snapshot(current_graph)
        changes: List[ChangeEvent] = []

        baseline_nodes = set(self.baseline_snapshot["nodes"].keys())
        current_nodes = set(current_snapshot["nodes"].keys())

        new_nodes = current_nodes - baseline_nodes
        removed_nodes = baseline_nodes - current_nodes

        # Process new nodes
        for node_id in new_nodes:
            node_data = current_snapshot["nodes"][node_id]
            node_type = node_data.get("type", "unknown")
            node_name = node_data.get("name", node_id)
            changes.append(ChangeEvent(
                change_type=f"new_{node_type}",
                description=f"New {node_type} added: '{node_name}' (ID: {node_id})",
                affected_entities=[node_id],
                severity="warning"
            ))

        # Process removed nodes
        for node_id in removed_nodes:
            node_data = self.baseline_snapshot["nodes"][node_id]
            node_type = node_data.get("type", "unknown")
            node_name = node_data.get("name", node_id)
            changes.append(ChangeEvent(
                change_type=f"removed_{node_type}",
                description=f"{node_type.capitalize()} removed: '{node_name}' (ID: {node_id})",
                affected_entities=[node_id],
                severity="critical"
            ))

        # Process edges
        baseline_edges = set(self.baseline_snapshot["edges"].keys())
        current_edges = set(current_snapshot["edges"].keys())

        new_edges = current_edges - baseline_edges
        removed_edges = baseline_edges - current_edges

        for edge_key in new_edges:
            edge_data = current_snapshot["edges"][edge_key]
            source_id, target_id = edge_key.split("->")
            rel = edge_data.get("relationship", "unknown")

            source_name = current_snapshot["nodes"].get(source_id, {}).get("name", source_id)
            target_name = current_snapshot["nodes"].get(target_id, {}).get("name", target_id)

            if rel == "COMMUNICATES":
                changes.append(ChangeEvent(
                    change_type="new_communication_path",
                    description=f"New data flow: {source_name} -> {target_name}",
                    affected_entities=[source_id, target_id],
                    severity="critical"
                ))
            else:
                changes.append(ChangeEvent(
                    change_type=f"new_{rel.lower()}_relationship",
                    description=f"New {rel} relationship: {source_name} -> {target_name}",
                    affected_entities=[source_id, target_id],
                    severity="info"
                ))

        for edge_key in removed_edges:
            edge_data = self.baseline_snapshot["edges"][edge_key]
            source_id, target_id = edge_key.split("->")
            source_name = self.baseline_snapshot["nodes"].get(source_id, {}).get("name", source_id)
            target_name = self.baseline_snapshot["nodes"].get(target_id, {}).get("name", target_id)
            changes.append(ChangeEvent(
                change_type="removed_path",
                description=f"Path removed: {source_name} -> {target_name}",
                affected_entities=[source_id, target_id],
                severity="warning"
            ))

        severity_order = {"critical": 0, "warning": 1, "info": 2}
        changes.sort(key=lambda c: severity_order.get(c.severity, 99))
        return changes

    def _snapshot(self, graph: SecurityGraph) -> Dict[str, Any]:
        nodes = {}
        for node_id, data in graph.graph.nodes(data=True):
            nodes[node_id] = {
                "type": data.get("type", "unknown"),
                "name": data.get("name", node_id),
                "status": data.get("status", "unknown")
            }

        edges = {}
        for u, v, data in graph.graph.edges(data=True):
            edge_key = f"{u}->{v}"
            edges[edge_key] = {
                "relationship": data.get("relationship", "unknown"),
                "protocol": data.get("protocol", ""),
                "path_id": data.get("path_id", "")
            }

        return {"nodes": nodes, "edges": edges}


import networkx as nx


class AssumptionAnalyzer:
    """
    Analyzes ChangeEvents to evaluate whether any declared security assumptions have been broken.
    Uses topology-aware graph analysis: only changes connected to an assumption's control
    or its protected assets/downstream data flow will flag the assumption.
    """

    def __init__(self, assumptions: List[Assumption]):
        self.assumptions = assumptions
        self.assumption_triggers = self._build_triggers()

    def _build_triggers(self) -> Dict[str, Dict[str, Any]]:
        triggers = {}
        for asm in self.assumptions:
            triggers[asm.assumption_id] = {
                "assumption": asm,
                "triggered_by": ["new_communication_path", "new_asset", "new_service", "removed_control"],
                "description": asm.description,
                "control_id": asm.related_control_id,
            }
        return triggers

    def _get_protected_enclave(self, control_id: str, graph: SecurityGraph) -> set:
        """
        Determine the security-relevant node cluster for a control:
        1. The control node itself.
        2. All assets directly protected by the control (PROTECTS edges).
        3. All downstream assets reachable from protected assets via COMMUNICATES edges.
        """
        enclave = {control_id}
        if control_id not in graph.graph:
            return enclave

        # Assets protected by this control
        protected_assets = set()
        for _, target, data in graph.graph.out_edges(control_id, data=True):
            if data.get("relationship") == "PROTECTS":
                protected_assets.add(target)

        enclave.update(protected_assets)

        # Downstream assets reachable from protected assets via data flows
        comm_edges = [
            (u, v) for u, v, d in graph.graph.edges(data=True)
            if d.get("relationship") == "COMMUNICATES"
        ]
        if comm_edges:
            comm_graph = nx.DiGraph(comm_edges)
            for pa in protected_assets:
                if pa in comm_graph:
                    try:
                        descendants = nx.descendants(comm_graph, pa)
                        enclave.update(descendants)
                    except Exception:
                        pass

        return enclave

    def _is_change_topologically_relevant(
        self,
        change: ChangeEvent,
        control_id: str,
        current_graph: SecurityGraph,
        baseline_graph: Optional[SecurityGraph] = None,
    ) -> bool:
        """
        Verify whether the entity/entities in change are connected to the protected enclave.
        """
        reference_graph = baseline_graph or current_graph
        enclave = self._get_protected_enclave(control_id, reference_graph)

        # Build communication graph of current state
        comm_edges = [
            (u, v) for u, v, d in current_graph.graph.edges(data=True)
            if d.get("relationship") == "COMMUNICATES"
        ]
        comm_graph = nx.DiGraph(comm_edges)

        # 1. Path changes (new data flow)
        if change.change_type == "new_communication_path":
            if len(change.affected_entities) >= 2:
                src, dst = change.affected_entities[0], change.affected_entities[1]
                # If path targets or originates from protected enclave
                if dst in enclave or src in enclave:
                    # Check if path passes through the required control
                    has_control = False
                    for _, ctrl, d in current_graph.graph.out_edges(src, data=True):
                        if ctrl == control_id and d.get("relationship") == "PASSES_THROUGH":
                            has_control = True
                            break
                    if not has_control:
                        return True
            return False

        # 2. Node changes (new asset / service)
        if change.change_type.startswith("new_"):
            for entity_id in change.affected_entities:
                if entity_id in enclave:
                    return True
                # Check if new node has communication paths to/from any node in the protected enclave
                if entity_id in comm_graph:
                    for target in enclave:
                        if target in comm_graph:
                            if nx.has_path(comm_graph, entity_id, target) or nx.has_path(comm_graph, target, entity_id):
                                return True
            return False

        # 3. Control removal
        if change.change_type == "removed_control":
            return control_id in change.affected_entities

        return True

    def analyze(
        self,
        changes: List[ChangeEvent],
        current_graph: Optional[SecurityGraph] = None,
        baseline_graph: Optional[SecurityGraph] = None,
    ) -> List[ChangeEvent]:
        """
        Evaluate changes and annotate any that break assumptions based on topological proximity.
        If current_graph is provided, applies topological relevance filtering.
        """
        for change in changes:
            for asm_id, trigger_info in self.assumption_triggers.items():
                if change.change_type in trigger_info["triggered_by"]:
                    # If topology graph is available, perform subgraph relevance check
                    if current_graph is not None:
                        ctrl_id = trigger_info["control_id"]
                        if not self._is_change_topologically_relevant(change, ctrl_id, current_graph, baseline_graph):
                            continue  # Unrelated change outside the assumption's security perimeter

                    change.potentially_breaks_assumptions = True
                    change.affected_assumption_id = asm_id
                    change.affected_assumption_desc = trigger_info["description"]
                    change.severity = "critical"
                    break
        return changes
