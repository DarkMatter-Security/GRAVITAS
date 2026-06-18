"""V4: Graph — Knowledge graph of entities, relationships, and attack paths.

Builds a NetworkX graph from V3 predictions and V2 entities.
Feeds graph_state into V5 Probability and V7 Digital Twin.

DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.config import get_config
from ..models import Prediction, ProcessedEvent, IntelligenceEntity

logger = logging.getLogger("gravitas.v4")


# ─── Relationship type definitions ────────────────────────────────

RELATION_WEIGHTS = {
    # Network relationships
    "connects_to": 1.0,
    "resolves_to": 0.8,
    "serves": 0.7,
    "routes_through": 0.6,
    # Security relationships
    "exploits": 1.0,
    "targets": 0.9,
    "scans": 0.7,
    "originates_from": 0.6,
    "compromises": 1.0,
    "is_vulnerable_to": 0.8,
    # Contextual relationships
    "same_network": 0.4,
    "same_owner": 0.5,
    "related_to": 0.3,
    "reports_to": 0.2,
    # Temporal / inference relationships
    "predicted_target": 0.6,
    "kill_chain_links": 0.9,
    "co_occurs_with": 0.3,
}


@dataclass
class GraphMetrics:
    """Computed graph-wide metrics."""
    num_nodes: int = 0
    num_edges: int = 0
    density: float = 0.0
    avg_degree: float = 0.0
    num_connected_components: int = 0
    num_high_risk_nodes: int = 0
    avg_risk_score: float = 0.0
    longest_attack_path: int = 0
    central_nodes: List[str] = field(default_factory=list)


class KnowledgeGraph:
    """Internal wrapper around NetworkX for the GRAVITAS intelligence graph.

    All graph operations happen here — thread-safe, with metrics tracking.
    """

    def __init__(self):
        self._nx = None  # Lazy import
        self._graph = None
        self._metrics = GraphMetrics()
        self._init_graph()

    def _init_graph(self):
        """Initialize the NetworkX graph."""
        try:
            import networkx as nx
            self._nx = nx
            self._graph = nx.MultiDiGraph()
            logger.debug("NetworkX graph initialized")
        except ImportError:
            logger.warning("NetworkX not installed — graph engine disabled")
            self._graph = None

    # ─── Node operations ───────────────────────────────────────────

    def add_entity(self, entity: IntelligenceEntity) -> bool:
        """Add or update an entity node. Returns True if new."""
        if self._graph is None:
            return False

        eid = entity.id
        is_new = eid not in self._graph

        attrs = {
            "type": entity.type,
            "name": entity.name,
            "confidence": entity.confidence,
            "tags": entity.tags,
            "properties": entity.properties,
            "first_seen": entity.first_seen,
            "last_seen": entity.last_seen,
        }

        if is_new:
            self._graph.add_node(eid, **attrs)
        else:
            # Merge properties — don't overwrite existing
            existing = dict(self._graph.nodes[eid])
            existing.update(attrs)
            # Keep earliest first_seen, latest last_seen
            existing["first_seen"] = min(
                existing["first_seen"], entity.first_seen
            )
            existing["last_seen"] = max(
                existing["last_seen"], entity.last_seen
            )
            # Merge tags
            existing["tags"] = list(set(existing.get("tags", [])) | set(entity.tags))
            existing["confidence"] = max(
                existing.get("confidence", 0), entity.confidence
            )
            self._graph.nodes[eid].update(existing)

        return is_new

    def add_prediction_nodes(self, predictions: List[Prediction]):
        """Add prediction-derived nodes (threat events)."""
        if self._graph is None:
            return

        for pred in predictions:
            node_id = f"prediction:{pred.id}"
            if node_id not in self._graph:
                self._graph.add_node(node_id, **{
                    "type": "prediction",
                    "name": f"{pred.prediction_type}:{pred.target}",
                    "prediction_type": pred.prediction_type,
                    "probability": pred.probability,
                    "confidence": pred.confidence,
                    "target": pred.target,
                    "time_horizon": pred.time_horizon,
                })

            # Link prediction to affected entities
            for entity_id in pred.affected_entities:
                self._add_edge(
                    node_id, entity_id,
                    rel_type="predicted_target",
                    weight=pred.probability,
                )

            # Link prediction to target entity if exists
            target_node = f"ip:{pred.target}" if "." in pred.target else None
            target_node = target_node or f"domain:{pred.target}"
            if target_node and target_node in self._graph:
                self._add_edge(
                    node_id, target_node,
                    rel_type="targets",
                    weight=pred.probability,
                )

    def add_correlation_edges(self, predictions: List[Prediction]):
        """Add edges between predictions that share entities (co-occurrence)."""
        if self._graph is None:
            return

        # Build entity → prediction map
        entity_to_preds: Dict[str, List[str]] = defaultdict(list)
        for pred in predictions:
            for eid in pred.affected_entities:
                entity_to_preds[eid].append(f"prediction:{pred.id}")

        # Connect predictions that share entities
        for eid, pred_ids in entity_to_preds.items():
            if len(pred_ids) > 1:
                for i in range(len(pred_ids)):
                    for j in range(i + 1, len(pred_ids)):
                        self._add_edge(
                            pred_ids[i], pred_ids[j],
                            rel_type="co_occurs_with",
                            weight=0.3,
                        )

    # ─── Edge operations ───────────────────────────────────────────

    def _add_edge(self, u: str, v: str, rel_type: str = "related_to",
                  weight: Optional[float] = None) -> None:
        """Add an edge with relationship type and weight."""
        if self._graph is None:
            return
        if u not in self._graph:
            self._graph.add_node(u, type="unknown", name=u)
        if v not in self._graph:
            self._graph.add_node(v, type="unknown", name=v)

        weight = weight or RELATION_WEIGHTS.get(rel_type, 0.5)
        self._graph.add_edge(u, v, key=rel_type, rel_type=rel_type, weight=weight)

    def add_entity_relation(self, eid1: str, eid2: str, rel_type: str) -> None:
        """Add a relationship between two existing entities."""
        weight = RELATION_WEIGHTS.get(rel_type, 0.5)
        self._add_edge(eid1, eid2, rel_type=rel_type, weight=weight)

    # ─── Analysis ──────────────────────────────────────────────────

    def compute_metrics(self) -> GraphMetrics:
        """Compute graph-wide metrics."""
        if self._graph is None or self._nx is None:
            return GraphMetrics()

        g = self._graph
        num_nodes = g.number_of_nodes()
        num_edges = g.number_of_edges()

        try:
            density = self._nx.density(g)
        except Exception:
            density = 0.0

        avg_degree = (2.0 * num_edges) / max(num_nodes, 1)

        try:
            components = list(self._nx.weakly_connected_components(g))
            num_components = len(components)
        except Exception:
            components = []
            num_components = 0

        # High-risk nodes (risk score > 0.7)
        high_risk = 0
        total_risk = 0.0
        for node, data in g.nodes(data=True):
            risk = data.get("confidence", 1.0)
            total_risk += risk
            if risk < 0.3:  # low confidence = high risk
                high_risk += 1

        # Central nodes (top 5 by degree centrality)
        central_nodes: List[str] = []
        try:
            centrality = self._nx.degree_centrality(g)
            central_nodes = [
                n for n, _ in sorted(
                    centrality.items(), key=lambda x: x[1], reverse=True
                )[:5]
            ]
        except Exception:
            pass

        # Longest attack path (longest shortest path in graph)
        longest_path = 0
        try:
            if num_nodes > 1 and num_components > 0:
                comp_sizes = [len(c) for c in components]
                longest_path = max(comp_sizes) - 1 if comp_sizes else 0
        except Exception:
            pass

        self._metrics = GraphMetrics(
            num_nodes=num_nodes,
            num_edges=num_edges,
            density=round(density, 6),
            avg_degree=round(avg_degree, 4),
            num_connected_components=num_components,
            num_high_risk_nodes=high_risk,
            avg_risk_score=round(total_risk / max(num_nodes, 1), 4),
            longest_attack_path=longest_path,
            central_nodes=central_nodes,
        )
        return self._metrics

    def get_attack_paths(self, source: str, target: str, max_depth: int = 5
                         ) -> List[List[str]]:
        """Find all attack paths between two nodes up to max_depth."""
        if self._graph is None or self._nx is None:
            return []

        try:
            paths = list(self._nx.all_simple_paths(
                self._graph, source=source, target=target,
                cutoff=max_depth,
            ))
            return paths
        except (self._nx.NetworkXNoPath, self._nx.NodeNotFound):
            return []
        except Exception as e:
            logger.warning("  Path analysis error: %s", e)
            return []

    def get_entity_context(self, entity_id: str, depth: int = 2) -> Dict[str, Any]:
        """Get the subgraph context around an entity."""
        if self._graph is None or self._nx is None:
            return {}

        try:
            neighbors = list(self._nx.ego_graph(self._graph, entity_id, radius=depth))
            subgraph = self._graph.subgraph(neighbors)

            entities = []
            for n, data in subgraph.nodes(data=True):
                entities.append({
                    "id": n,
                    "type": data.get("type", "unknown"),
                    "name": data.get("name", n),
                })

            edges = []
            for u, v, data in subgraph.edges(data=True):
                edges.append({
                    "source": u,
                    "target": v,
                    "rel_type": data.get("rel_type", "related_to"),
                    "weight": data.get("weight", 0.5),
                })

            return {
                "center_entity": entity_id,
                "neighbors": len(neighbors) - 1,  # exclude self
                "entities": entities,
                "edges": edges,
            }
        except Exception as e:
            logger.warning("  Ego graph error: %s", e)
            return {}

    def to_dict(self) -> Dict[str, Any]:
        """Export graph to serializable dict."""
        if self._graph is None:
            return {"status": "disabled", "nodes": 0, "edges": 0}

        nodes_list = []
        for n, data in self._graph.nodes(data=True):
            nodes_list.append({
                "id": n,
                "type": data.get("type", "unknown"),
                "name": data.get("name", n),
                "confidence": data.get("confidence", 1.0),
            })

        edges_list = []
        for u, v, k, data in self._graph.edges(data=True, keys=True):
            edges_list.append({
                "source": u,
                "target": v,
                "rel_type": data.get("rel_type", "related_to"),
                "weight": data.get("weight", 0.5),
            })

        return {
            "status": "active",
            "nodes": len(nodes_list),
            "edges": len(edges_list),
            "node_list": nodes_list[:100],  # Limit for serialization
            "edge_list": edges_list[:200],
            "metrics": {
                "density": self._metrics.density,
                "avg_degree": self._metrics.avg_degree,
                "num_components": self._metrics.num_connected_components,
                "high_risk_nodes": self._metrics.num_high_risk_nodes,
                "central_nodes": self._metrics.central_nodes,
            },
        }


class GraphEngine:
    """V4: Knowledge graph of entities, relationships, and attack paths.

    Input:  List[Prediction] from V3 Inference (+ List[ProcessedEvent] for entities)
    Output: Dict[str, Any] graph_state → feeds V5 Probability and V7 Digital Twin
    """

    def __init__(self):
        self.config = get_config()
        self.graph = KnowledgeGraph()

        self._stats: Dict[str, Any] = {
            "total_nodes": 0,
            "total_edges": 0,
            "predictions_ingested": 0,
            "entities_ingested": 0,
            "build_time_ms": 0.0,
            "metrics": {},
        }

    async def build(self, predictions: List[Prediction],
                    entities: Optional[List[IntelligenceEntity]] = None) -> Dict[str, Any]:
        """Build or update the intelligence graph.

        Args:
            predictions: List of Prediction objects from V3 Inference.
            entities: Optional list of IntelligenceEntity objects from V2 Processing.

        Returns:
            Graph state dict with metrics, ready for V5/V7 consumption.
        """
        start = time.time()
        logger.info(
            "V4 Building knowledge graph from %d prediction(s), %d entit(ies)",
            len(predictions),
            len(entities) if entities else 0,
        )

        if not predictions and not entities:
            logger.info("  Nothing to graph — returning current state")
            return self.graph.to_dict()

        # Add entities as nodes
        entity_count = 0
        if entities:
            for entity in entities:
                if self.graph.add_entity(entity):
                    entity_count += 1

        # Add predictions as nodes + edges
        pred_count = 0
        if predictions:
            self.graph.add_prediction_nodes(predictions)
            self.graph.add_correlation_edges(predictions)
            pred_count = len(predictions)

        # Build entity relations from prediction links
        for pred in predictions:
            affected = pred.affected_entities
            for i in range(len(affected)):
                for j in range(i + 1, len(affected)):
                    self.graph.add_entity_relation(
                        affected[i], affected[j], "co_occurs_with"
                    )

        # Compute metrics
        metrics = self.graph.compute_metrics()

        elapsed_ms = (time.time() - start) * 1000
        self._stats = {
            "total_nodes": metrics.num_nodes,
            "total_edges": metrics.num_edges,
            "predictions_ingested": pred_count,
            "entities_ingested": entity_count,
            "build_time_ms": round(elapsed_ms, 2),
            "metrics": {
                "density": metrics.density,
                "avg_degree": metrics.avg_degree,
                "num_components": metrics.num_connected_components,
                "high_risk_nodes": metrics.num_high_risk_nodes,
                "central_nodes": metrics.central_nodes,
                "longest_attack_path": metrics.longest_attack_path,
            },
        }

        logger.info(
            "V4 complete: %d nodes | %d edges | density=%.4f | "
            "%d components | %.0fms",
            metrics.num_nodes, metrics.num_edges, metrics.density,
            metrics.num_connected_components, elapsed_ms,
        )

        return self.graph.to_dict()

    def find_paths(self, source: str, target: str) -> List[List[str]]:
        """Find attack paths between two entities."""
        return self.graph.get_attack_paths(source, target)

    def entity_context(self, entity_id: str) -> Dict[str, Any]:
        """Get subgraph context around an entity."""
        return self.graph.get_entity_context(entity_id)

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)
