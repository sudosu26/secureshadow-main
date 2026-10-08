"""
SECURESHADOW - Graph Engine
Builds and queries the architecture and security dependency graph using NetworkX.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
import networkx as nx

from .models import Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath


class SecurityGraph:
    """
    A typed directed graph representing:
    - Nodes: Assets, SecurityControls, Assumptions
    - Edges: Communication paths (COMMUNICATES), Control protection (PROTECTS),
      Path inspection (PASSES_THROUGH), Assumption dependencies (DEPENDS_ON).
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.build_time = datetime.now()
        self._communication_cache: Optional[nx.DiGraph] = None
        self._protected_assets_cache: Dict[str, set[str]] = {}

    def _invalidate_caches(self) -> None:
        """Invalidate derived graph caches after topology changes."""
        self._communication_cache = None
        self._protected_assets_cache.clear()

    def add_asset(self, asset: Asset) -> None:
        """Add an asset node to the graph."""
        self.graph.add_node(
            asset.asset_id,
            type="asset",
            name=asset.name,
            asset_type=asset.asset_type,
            ip=asset.ip_address,
            label=f"{asset.name}\n({asset.asset_type})"
        )
        self._invalidate_caches()

    def add_control(self, control: SecurityControl) -> None:
        """Add a security control node and edges to protected assets."""
        self.graph.add_node(
            control.control_id,
            type="control",
            name=control.name,
            control_type=control.control_type,
            status=control.status,
            label=f"{control.name}\n({control.control_type})"
        )
        for asset in control.protects:
            self.graph.add_edge(
                control.control_id,
                asset.asset_id,
                relationship="PROTECTS",
                label="PROTECTS"
            )
        self._invalidate_caches()

    def add_assumption(self, assumption: Assumption) -> None:
        """Add an assumption node and link it to its associated control."""
        node_id = assumption.assumption_id
        self.graph.add_node(
            node_id,
            type="assumption",
            description=assumption.description,
            is_valid=assumption.is_valid,
            label=f"Assumption:\n{assumption.description[:40]}..."
        )
        self.graph.add_edge(
            node_id,
            assumption.related_control_id,
            relationship="DEPENDS_ON",
            label="DEPENDS_ON"
        )
        self._invalidate_caches()

    def add_path(self, path: CommunicationPath) -> None:
        """Add a communication path as an edge between assets."""
        self.graph.add_edge(
            path.source.asset_id,
            path.destination.asset_id,
            relationship="COMMUNICATES",
            protocol=path.protocol,
            path_id=path.path_id,
            label=f"{path.protocol}"
        )
        for control in path.passes_through:
            self.graph.add_edge(
                path.source.asset_id,
                control.control_id,
                relationship="PASSES_THROUGH",
                label="PASSES_THROUGH"
            )
        self._invalidate_caches()

    def get_communication_graph(self) -> nx.DiGraph:
        """Return a lightweight view of only COMMUNICATES edges for path analysis."""
        if self._communication_cache is None:
            communication_graph = nx.DiGraph()
            for source, target, data in self.graph.edges(data=True):
                if data.get("relationship") == "COMMUNICATES":
                    communication_graph.add_edge(
                        source,
                        target,
                        protocol=data.get("protocol", ""),
                        path_id=data.get("path_id", ""),
                        relationship="COMMUNICATES",
                    )
            self._communication_cache = communication_graph
        return self._communication_cache.copy()

    def get_protected_assets(self, control_id: str) -> set[str]:
        """Return all assets directly protected by a control, cached for repeated checks."""
        if control_id not in self._protected_assets_cache:
            protected_assets = {
                target for _, target, data in self.graph.out_edges(control_id, data=True)
                if data.get("relationship") == "PROTECTS"
            }
            self._protected_assets_cache[control_id] = protected_assets
        return set(self._protected_assets_cache[control_id])

    def find_paths_between(self, source_id: str, target_id: str, cutoff: int = 5) -> List[List[str]]:
        """
        Find all communication paths between two assets to detect bypass routes.
        """
        try:
            return list(nx.all_simple_paths(self.graph, source_id, target_id, cutoff=cutoff))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def find_controls_protecting(self, asset_id: str) -> List[str]:
        """Find all security controls that protect a given asset."""
        if asset_id not in self.graph:
            return []
        return [
            source for source, _, data in self.graph.in_edges(asset_id, data=True)
            if data.get("relationship") == "PROTECTS"
        ]

    def get_protection_summary(self, asset_id: str) -> Dict[str, Any]:
        """Get a protection overview for a specific asset."""
        if asset_id not in self.graph:
            return {"asset": asset_id, "protecting_controls": [], "control_count": 0}
        controls = self.find_controls_protecting(asset_id)
        return {
            "asset": self.graph.nodes[asset_id].get("name", asset_id),
            "protecting_controls": [
                self.graph.nodes[c].get("name", c) for c in controls
            ],
            "control_count": len(controls)
        }

    def find_all_paths_to_asset(self, asset_id: str, cutoff: int = 5) -> List[List[str]]:
        """Find all paths from any node leading to a target asset using the communication graph."""
        if asset_id not in self.graph:
            return []

        communication_graph = self.get_communication_graph()
        if asset_id not in communication_graph:
            return []

        all_paths: List[List[str]] = []
        for node in communication_graph.nodes:
            if node == asset_id:
                continue
            if not nx.has_path(communication_graph, node, asset_id):
                continue
            try:
                all_paths.extend(nx.all_simple_paths(communication_graph, node, asset_id, cutoff=cutoff))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass
        return all_paths

    def get_graph_stats(self) -> Dict[str, Any]:
        """Return topology metrics for the security graph."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_types": self._count_node_types(),
            "edge_relationships": self._count_edge_types()
        }

    def _count_node_types(self) -> Dict[str, int]:
        types: Dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            types[node_type] = types.get(node_type, 0) + 1
        return types

    def _count_edge_types(self) -> Dict[str, int]:
        rels: Dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            rel = data.get("relationship", "unknown")
            rels[rel] = rels.get(rel, 0) + 1
        return rels
