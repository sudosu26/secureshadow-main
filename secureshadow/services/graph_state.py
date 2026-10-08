"""Persistence helpers for the authoritative baseline and current graph snapshots."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..db.models import GraphSnapshotModel
from ..graph import SecurityGraph


def serialize_graph(graph: SecurityGraph) -> dict[str, Any]:
    """Convert graph topology and attributes to JSON-compatible data."""
    return {
        "nodes": [
            {"id": node_id, **dict(attributes)}
            for node_id, attributes in graph.graph.nodes(data=True)
        ],
        "edges": [
            {"source": source, "target": target, **dict(attributes)}
            for source, target, attributes in graph.graph.edges(data=True)
        ],
    }


def deserialize_graph(graph_data: dict[str, Any]) -> SecurityGraph:
    """Rebuild a SecurityGraph from a persisted snapshot."""
    graph = SecurityGraph()
    for node in graph_data.get("nodes", []):
        attributes = dict(node)
        node_id = attributes.pop("id")
        graph.graph.add_node(node_id, **attributes)
    for edge in graph_data.get("edges", []):
        attributes = dict(edge)
        source = attributes.pop("source")
        target = attributes.pop("target")
        graph.graph.add_edge(source, target, **attributes)
    graph._invalidate_caches()
    return graph


def clone_graph(graph: SecurityGraph) -> SecurityGraph:
    """Create an independent graph copy without carrying derived caches."""
    return deserialize_graph(serialize_graph(graph))


def persist_security_definitions(
    db: Session,
    assumptions: list[Any],
    properties: list[Any],
) -> None:
    """Persist the security definitions associated with the approved baseline."""
    db.flush()
    snapshot = db.get(GraphSnapshotModel, "baseline")
    if snapshot is None:
        raise ValueError("Cannot persist security definitions without a baseline snapshot.")
    snapshot.graph_data = {
        **snapshot.graph_data,
        "assumptions": [assumption.to_dict() for assumption in assumptions],
        "properties": [security_property.to_dict() for security_property in properties],
    }
    snapshot.updated_at = datetime.now(timezone.utc)


def persist_graph_snapshot(
    db: Session,
    snapshot_name: str,
    graph: SecurityGraph,
) -> None:
    """Stage a graph snapshot update; the caller controls transaction commit."""
    snapshot = db.get(GraphSnapshotModel, snapshot_name)
    if snapshot is None:
        snapshot = GraphSnapshotModel(snapshot_name=snapshot_name, graph_data=serialize_graph(graph))
        db.add(snapshot)
    else:
        snapshot.graph_data = serialize_graph(graph)
        snapshot.updated_at = datetime.now(timezone.utc)


def load_graph_snapshot(db: Session, snapshot_name: str) -> SecurityGraph | None:
    snapshot = db.get(GraphSnapshotModel, snapshot_name)
    if snapshot is None:
        return None
    return deserialize_graph(snapshot.graph_data)
