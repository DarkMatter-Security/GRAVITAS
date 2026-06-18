"""V7: Digital Twin — Virtual representation of target environment with state mirroring and what-if simulation.

Maintains a real-time digital twin of monitored infrastructure,
enabling simulation, state introspection, and predictive analysis.

Input:  scores (V5), temporal (V6), graph_state (V4)
Output: Dict[str, Any] twin_state → feeds V8 Autonomous for self-acting defense

DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

from __future__ import annotations

import copy
import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum

from ..core.config import get_config

logger = logging.getLogger("gravitas.v7")


# ─── Twin State Definitions ───────────────────────────────────────


class EntityState(Enum):
    """Possible states for a digital twin entity."""
    ACTIVE = "active"
    COMPROMISED = "compromised"
    VULNERABLE = "vulnerable"
    PATCHED = "patched"
    UNKNOWN = "unknown"
    DECOMMISSIONED = "decommissioned"
    ISOLATED = "isolated"
    MONITORING = "monitoring"


@dataclass
class TwinEntity:
    """A single entity in the digital twin (server, service, network segment, etc.)."""
    id: str
    name: str
    entity_type: str  # host, service, network, application, user
    state: EntityState = EntityState.UNKNOWN
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 1.0
    last_updated: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    dependencies: List[str] = field(default_factory=list)  # IDs of dependant entities
    exposed_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d


@dataclass
class EnvironmentSnapshot:
    """A point-in-time snapshot of the entire digital twin environment."""
    timestamp: float
    entities: Dict[str, TwinEntity]
    overall_health: float  # 0.0–1.0
    critical_entities: int
    compromised_count: int
    vulnerable_count: int
    active_count: int
    avg_risk: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "overall_health": self.overall_health,
            "critical_entities": self.critical_entities,
            "compromised_count": self.compromised_count,
            "vulnerable_count": self.vulnerable_count,
            "active_count": self.active_count,
            "avg_risk": self.avg_risk,
            "total_entities": len(self.entities),
        }


class WhatIfSimulation:
    """Run 'what-if' scenarios on the digital twin without affecting live state."""

    def __init__(self, twin: "DigitalTwinEngine"):
        self.twin = twin

    def simulate_compromise(self, entity_id: str) -> Dict[str, Any]:
        """Simulate what happens if an entity is compromised."""
        state = self.twin._state
        if entity_id not in state["entities"]:
            return {"error": f"Entity {entity_id} not found"}

        sim_entities = copy.deepcopy(state["entities"])
        original = sim_entities[entity_id]
        original.state = EntityState.COMPROMISED

        # Propagate: mark dependent entities as compromised too
        cascade = [entity_id]
        affected = []
        for eid, entity in sim_entities.items():
            if entity_id in entity.dependencies:
                entity.state = EntityState.COMPROMISED
                entity.risk_score = min(1.0, original.risk_score + 0.3)
                cascade.append(eid)
                affected.append({
                    "id": eid,
                    "name": entity.name,
                    "old_risk": entity.risk_score - 0.3,
                    "new_risk": entity.risk_score,
                })

        # Compute simulated health
        health = self._compute_health(sim_entities)

        return {
            "simulation_type": "compromise",
            "trigger_entity": entity_id,
            "cascade_size": len(cascade),
            "affected_entities": cascade,
            "details": affected,
            "simulated_health": round(health, 4),
            "risk_delta": round(
                sum(a["new_risk"] - a["old_risk"] for a in affected), 4
            ),
        }

    def simulate_patch(self, entity_id: str, vulnerability_id: str) -> Dict[str, Any]:
        """Simulate patching a vulnerability on an entity."""
        state = self.twin._state
        if entity_id not in state["entities"]:
            return {"error": f"Entity {entity_id} not found"}

        sim_entities = copy.deepcopy(state["entities"])
        entity = sim_entities[entity_id]

        if vulnerability_id in entity.vulnerabilities:
            entity.vulnerabilities.remove(vulnerability_id)
            entity.risk_score = max(0.0, entity.risk_score - 0.2)

        # Recompute state
        if not entity.vulnerabilities and entity.risk_score < 0.3:
            entity.state = EntityState.PATCHED

        health = self._compute_health(sim_entities)

        return {
            "simulation_type": "patch",
            "trigger_entity": entity_id,
            "patched_vulnerability": vulnerability_id,
            "remaining_vulnerabilities": entity.vulnerabilities,
            "new_risk": round(entity.risk_score, 4),
            "risk_reduction": 0.2,
            "simulated_health": round(health, 4),
        }

    def simulate_isolation(self, entity_id: str) -> Dict[str, Any]:
        """Simulate isolating an entity from the network."""
        state = self.twin._state
        if entity_id not in state["entities"]:
            return {"error": f"Entity {entity_id} not found"}

        sim_entities = copy.deepcopy(state["entities"])
        entity = sim_entities[entity_id]
        entity.state = EntityState.ISOLATED
        entity.risk_score = 0.0  # No risk if isolated
        entity.exposed_ports = []

        # Remove dependency edges TO this entity from others
        for eid, other in sim_entities.items():
            if entity_id in other.dependencies:
                other.dependencies.remove(entity_id)

        health = self._compute_health(sim_entities)

        return {
            "simulation_type": "isolation",
            "trigger_entity": entity_id,
            "simulated_health": round(health, 4),
            "risk_reduction": round(original_risk - entity.risk_score, 4)
            if (original_risk := state["entities"].get(entity_id, TwinEntity(id="", name="")).risk_score)
            else 0.0,
        }

    @staticmethod
    def _compute_health(entities: Dict[str, TwinEntity]) -> float:
        """Compute overall environment health from entity states."""
        if not entities:
            return 1.0

        total = len(entities)
        compromised = sum(
            1 for e in entities.values()
            if e.state == EntityState.COMPROMISED
        )
        vulnerable = sum(
            1 for e in entities.values()
            if e.state == EntityState.VULNERABLE
        )
        isolated = sum(
            1 for e in entities.values()
            if e.state == EntityState.ISOLATED
        )
        active_healthy = sum(
            1 for e in entities.values()
            if e.state == EntityState.ACTIVE
        )

        # Health = (healthy + isolated) / total, penalized by compromised
        health = (active_healthy + isolated * 0.7 - compromised * 0.5) / total
        return max(0.0, min(1.0, health))


class DigitalTwinEngine:
    """V7: Digital Twin — Virtual representation of target environment.

    Maintains a real-time mirror of the monitored infrastructure,
    tracking entity states, risk levels, and enabling what-if analysis.

    Input:  scores (V5), temporal (V6), graph_state (V4)
    Output: Dict[str, Any] twin_state → feeds V8 Autonomous Engine
    """

    def __init__(self):
        self.config = get_config()
        self._lock = threading.Lock()
        self._state: Dict[str, Any] = {
            "entities": {},
            "snapshots": [],
            "current_snapshot": None,
            "last_sync": 0.0,
            "sync_count": 0,
        }
        self._simulator = WhatIfSimulation(self)
        self._entity_id_counter: Dict[str, int] = defaultdict(int)

        self._stats: Dict[str, Any] = {
            "total_entities": 0,
            "total_snapshots": 0,
            "sync_count": 0,
            "compromised_count": 0,
            "vulnerable_count": 0,
            "overall_health": 1.0,
            "avg_risk": 0.0,
            "sync_time_ms": 0.0,
        }

    # ─── Entity Management ─────────────────────────────────────────

    def _get_or_create_entity(self, entity_id: str, entity_type: str = "unknown",
                              name: str = "") -> TwinEntity:
        """Get existing entity or create a new one."""
        with self._lock:
            if entity_id in self._state["entities"]:
                return self._state["entities"][entity_id]

            entity = TwinEntity(
                id=entity_id,
                name=name or entity_id,
                entity_type=entity_type,
                state=EntityState.ACTIVE,
            )
            self._state["entities"][entity_id] = entity
            return entity

    def _update_entity_from_score(self, score_dict: Dict[str, Any]):
        """Update or create a twin entity from a V5 score dict."""
        target = score_dict.get("target", "unknown")
        # Determine entity type from score data
        node_type = score_dict.get("node_type", "unknown")

        # Generate a stable entity ID
        eid = f"{node_type}:{target}"

        entity = self._get_or_create_entity(eid, node_type, target)

        # Update state based on risk
        risk = score_dict.get("risk", 0.0)
        entity.risk_score = max(entity.risk_score, risk)
        entity.confidence = min(entity.confidence, score_dict.get("confidence", 1.0))
        entity.last_seen = time.time()

        # Determine state from risk level
        risk_level = score_dict.get("risk_level", "low")
        if risk_level == "critical":
            entity.state = EntityState.COMPROMISED
        elif risk_level == "high":
            entity.state = EntityState.VULNERABLE
        elif risk_level == "medium":
            entity.state = EntityState.MONITORING
        else:
            entity.state = EntityState.ACTIVE

        # Track vulnerabilities
        if node_type == "vulnerability" and entity.vulnerabilities:
            v_id = target
            if v_id not in entity.vulnerabilities:
                entity.vulnerabilities.append(v_id)

        # Update metadata
        entity.metadata["last_score_update"] = time.time()
        entity.metadata["risk_sources"] = score_dict.get("contributing_factors", [])

    def _update_from_graph(self, graph_state: Dict[str, Any]):
        """Incorporate graph entity data into the digital twin."""
        node_list = graph_state.get("node_list", [])
        for node in node_list:
            node_id = node.get("id", "")
            node_type = node.get("type", "unknown")
            node_name = node.get("name", node_id)

            eid = f"{node_type}:{node_name}"
            entity = self._get_or_create_entity(eid, node_type, node_name)

            # Merge confidence
            confidence = node.get("confidence", 1.0)
            entity.confidence = min(entity.confidence, confidence)

            # Track as related entity in metadata
            if "graph_node_id" not in entity.metadata:
                entity.metadata["graph_node_id"] = node_id

    def _update_from_temporal(self, temporal_state: Dict[str, Any]):
        """Incorporate temporal analysis into the digital twin."""
        summary = temporal_state.get("summary", {})
        trend_direction = summary.get("trend_direction", "stable")
        next_window = summary.get("next_window")

        # Create/update a meta-entity for "environment", not external entity
        # Store temporal context in twin metadata
        with self._lock:
            self._state["temporal_context"] = {
                "trend_direction": trend_direction,
                "next_predicted_window": next_window,
                "total_events": summary.get("total_events", 0),
                "time_span_hours": summary.get("time_span_hours", 0),
            }

    # ─── Sync ──────────────────────────────────────────────────────

    async def sync(self, intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Sync the digital twin with real-world intelligence data.

        Args:
            intelligence: Dict with keys:
                - 'scores': List[Dict] from V5 Probability Engine
                - 'temporal': Dict from V6 Temporal Engine
                - 'graph': Dict from V4 Graph Engine (optional)

        Returns:
            Dict with current twin state for downstream use (V8).
        """
        start = time.time()
        logger.info("V7 Digital Twin syncing with intelligence feed")

        scores = intelligence.get("scores", [])
        temporal = intelligence.get("temporal", {})
        graph = intelligence.get("graph", {})

        # Update entities from scores
        score_count = 0
        for score_dict in scores:
            try:
                self._update_entity_from_score(score_dict)
                score_count += 1
            except Exception as e:
                logger.warning("  Error updating entity from score: %s", e)

        # Incorporate graph data
        if graph:
            try:
                self._update_from_graph(graph)
            except Exception as e:
                logger.warning("  Error updating from graph: %s", e)

        # Incorporate temporal analysis
        if temporal:
            try:
                self._update_from_temporal(temporal)
            except Exception as e:
                logger.warning("  Error updating from temporal: %s", e)

        # Take a snapshot
        snapshot = self._take_snapshot()

        elapsed_ms = (time.time() - start) * 1000
        with self._lock:
            self._state["last_sync"] = time.time()
            self._state["sync_count"] += 1

        self._stats["sync_count"] += 1
        self._stats["total_entities"] = len(self._state["entities"])
        self._stats["total_snapshots"] = len(self._state["snapshots"])
        self._stats["compromised_count"] = snapshot.compromised_count
        self._stats["vulnerable_count"] = snapshot.vulnerable_count
        self._stats["overall_health"] = round(snapshot.overall_health, 4)
        self._stats["avg_risk"] = round(snapshot.avg_risk, 4)
        self._stats["sync_time_ms"] = round(elapsed_ms, 2)

        logger.info(
            "V7 sync complete: %d entities | %d compromised | %d vulnerable | "
            "health=%.3f | %.0fms",
            len(self._state["entities"]),
            snapshot.compromised_count,
            snapshot.vulnerable_count,
            snapshot.overall_health,
            elapsed_ms,
        )

        return {
            "status": "synced",
            "timestamp": time.time(),
            "entities": snapshot.total_entities if hasattr(snapshot, 'total_entities') else len(self._state["entities"]),
            "overall_health": snapshot.overall_health,
            "compromised": snapshot.compromised_count,
            "vulnerable": snapshot.vulnerable_count,
            "avg_risk": snapshot.avg_risk,
            "twin": self.get_state(),
        }

    # ─── Snapshot Management ───────────────────────────────────────

    def _take_snapshot(self) -> EnvironmentSnapshot:
        """Take a point-in-time snapshot of the current twin state."""
        with self._lock:
            entities = copy.deepcopy(self._state["entities"])

        if not entities:
            snapshot = EnvironmentSnapshot(
                timestamp=time.time(), entities={},
                overall_health=1.0, critical_entities=0,
                compromised_count=0, vulnerable_count=0,
                active_count=0, avg_risk=0.0,
            )
        else:
            total = len(entities)
            compromised = sum(
                1 for e in entities.values()
                if e.state == EntityState.COMPROMISED
            )
            vulnerable = sum(
                1 for e in entities.values()
                if e.state == EntityState.VULNERABLE
            )
            active = sum(
                1 for e in entities.values()
                if e.state == EntityState.ACTIVE
            )
            isolated = sum(
                1 for e in entities.values()
                if e.state == EntityState.ISOLATED
            )
            monitoring = sum(
                1 for e in entities.values()
                if e.state == EntityState.MONITORING
            )
            avg_risk = sum(e.risk_score for e in entities.values()) / max(total, 1)

            # Health: active + isolated*0.7 + monitoring*0.5 - compromised*0.5 - vulnerable*0.3
            health = (
                active + isolated * 0.7 + monitoring * 0.5
                - compromised * 0.5 - vulnerable * 0.3
            ) / max(total, 1)
            health = max(0.0, min(1.0, health))

            snapshot = EnvironmentSnapshot(
                timestamp=time.time(),
                entities=entities,
                overall_health=round(health, 4),
                critical_entities=compromised + vulnerable,
                compromised_count=compromised,
                vulnerable_count=vulnerable,
                active_count=active,
                avg_risk=round(avg_risk, 4),
            )

        # Keep last 50 snapshots
        with self._lock:
            self._state["snapshots"].append(snapshot)
            if len(self._state["snapshots"]) > 50:
                self._state["snapshots"] = self._state["snapshots"][-50:]
            self._state["current_snapshot"] = snapshot

        return snapshot

    # ─── State Queries ─────────────────────────────────────────────

    def get_state(self) -> Dict[str, Any]:
        """Get the current digital twin state (serializable)."""
        with self._lock:
            entities = {
                eid: entity.to_dict()
                for eid, entity in self._state["entities"].items()
            }
            snapshot = self._state.get("current_snapshot")
            temporal = self._state.get("temporal_context", {})

        return {
            "timestamp": time.time(),
            "entities": entities,
            "total_entities": len(entities),
            "snapshot": snapshot.to_dict() if snapshot else {},
            "temporal_context": temporal,
            "stats": dict(self._stats),
        }

    def get_entity(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific entity from the twin."""
        with self._lock:
            entity = self._state["entities"].get(entity_id)
        return entity.to_dict() if entity else None

    def get_snapshot_history(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get the last N snapshots."""
        with self._lock:
            snapshots = self._state["snapshots"][-count:]
        return [s.to_dict() for s in snapshots]

    # ─── What-If Simulations ───────────────────────────────────────

    def what_if(self, scenario: str, target_id: str,
                params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run a what-if simulation scenario.

        Args:
            scenario: 'compromise', 'patch', 'isolate'
            target_id: Entity ID to simulate on
            params: Optional extra parameters (e.g., vulnerability_id for patch)

        Returns:
            Simulation result dict.
        """
        params = params or {}
        logger.info("V7 What-if simulation: %s on %s", scenario, target_id)

        if scenario == "compromise":
            return self._simulator.simulate_compromise(target_id)
        elif scenario == "patch":
            vuln_id = params.get("vulnerability_id", "")
            return self._simulator.simulate_patch(target_id, vuln_id)
        elif scenario == "isolate":
            return self._simulator.simulate_isolation(target_id)
        else:
            return {"error": f"Unknown scenario: {scenario}"}

    # ─── Properties ────────────────────────────────────────────────

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    @property
    def entity_count(self) -> int:
        with self._lock:
            return len(self._state["entities"])

    @property
    def overall_health(self) -> float:
        return self._stats["overall_health"]
