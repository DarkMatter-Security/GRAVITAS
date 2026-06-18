"""V5: Probability — Risk scoring, Bayesian prediction, and threat likelihood.

Feeds scored predictions into V6 Temporal, V7 Digital Twin, and V8 Autonomous.

Input:  Dict[str, Any] graph_state from V4 Graph
Output: List[Dict] scored predictions → feeds V6+, V8 for autonomous action

DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

from __future__ import annotations

import json
import logging
import math
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

from ..core.config import get_config

logger = logging.getLogger("gravitas.v5")


# ─── Risk level thresholds ────────────────────────────────────────

RISK_LEVELS = {
    "critical": (0.9, 1.0),
    "high": (0.7, 0.9),
    "medium": (0.4, 0.7),
    "low": (0.1, 0.4),
    "negligible": (0.0, 0.1),
}


@dataclass
class ScoredEntity:
    """An entity with computed risk/probability scores."""
    target: str
    risk_score: float
    probability: float
    confidence: float
    risk_level: str
    contributing_factors: List[str] = field(default_factory=list)
    prediction_id: str = ""
    prediction_type: str = "risk_assessment"
    node_type: str = "unknown"
    graph_centrality: float = 0.0
    num_connections: int = 0


class BayesRiskModel:
    """Bayesian risk model combining prior and evidence.

    Uses a simplified Naive Bayes approach:
      P(threat | evidence) ∝ P(threat) × P(evidence | threat)

    Where:
      - Prior P(threat) = baseline risk (from graph metrics / heuristics)
      - Likelihood P(evidence | threat) = signal from multiple evidence sources
    """

    # Baseline priors by entity type
    TYPE_PRIORS = {
        "ip": 0.15,
        "domain": 0.20,
        "vulnerability": 0.60,
        "prediction": 0.40,
        "port": 0.10,
        "unknown": 0.10,
    }

    def __init__(self):
        self._evidence_counts: Dict[str, int] = defaultdict(int)
        self._threat_counts: Dict[str, int] = defaultdict(int)
        self._total_updates: int = 0

    def compute_posterior(self, evidence_scores: List[float],
                          entity_type: str = "unknown",
                          base_risk: float = 0.0) -> float:
        """Compute posterior threat probability given multiple evidence scores.

        Args:
            evidence_scores: List of evidence signals (0.0–1.0 each).
            entity_type: Type of entity being scored.
            base_risk: Pre-computed base risk (e.g., from graph analysis).

        Returns:
            Posterior probability 0.0–1.0.
        """
        # Prior
        prior = self.TYPE_PRIORS.get(entity_type, 0.15)
        if base_risk > 0:
            # Blend graph-derived risk with type prior
            prior = 0.4 * prior + 0.6 * min(base_risk, 1.0)

        if not evidence_scores:
            return prior

        # Combine evidence: use noise-robust averaging
        # Sort and take top 3 evidence signals (most relevant)
        sorted_scores = sorted(evidence_scores, reverse=True)[:3]
        evidence_strength = sum(sorted_scores) / max(len(sorted_scores), 1)

        # Bayesian update: posterior = prior × likelihood / evidence
        # Simplified: weighted blend with evidence dominance
        posterior = prior * (1 - evidence_strength) + evidence_strength
        # Clamp
        posterior = min(max(posterior, 0.0), 1.0)

        # Update learning counts
        self._evidence_counts[entity_type] += len(evidence_scores)
        self._threat_counts[entity_type] += 1 if posterior > 0.5 else 0
        self._total_updates += 1

        return round(posterior, 4)

    def get_type_prior(self, entity_type: str) -> float:
        """Get the current empirical prior for an entity type."""
        total = self._evidence_counts.get(entity_type, 0)
        threats = self._threat_counts.get(entity_type, 0)
        if total > 10:
            return threats / total
        return self.TYPE_PRIORS.get(entity_type, 0.15)


class RiskScorer:
    """Score graph entities for risk using multiple evidence axes."""

    # Evidence weights for different axes
    EVIDENCE_WEIGHTS = {
        "graph_centrality": 0.15,
        "kill_chain_coverage": 0.30,
        "vulnerability_count": 0.25,
        "anomaly_score": 0.20,
        "connection_density": 0.10,
    }

    def score_node(self, node_id: str, node_data: Dict[str, Any],
                   graph_state: Dict[str, Any]) -> ScoredEntity:
        """Score a single graph node for risk."""
        evidence: List[float] = []
        factors: List[str] = []

        # Axis 1: Node type base risk
        node_type = node_data.get("type", "unknown")
        if node_type == "vulnerability":
            evidence.append(0.7)
            factors.append("vulnerability_node")
        elif node_type == "prediction":
            evidence.append(node_data.get("probability", 0.4))
            factors.append(f"prediction_prob:{node_data.get('probability', 0.4):.2f}")

        # Axis 2: Graph centrality
        metrics = graph_state.get("metrics", {})
        central_nodes = metrics.get("central_nodes", [])
        if node_id in central_nodes:
            evidence.append(0.6)
            factors.append("high_centrality")
        else:
            evidence.append(0.1)

        # Axis 3: Confidence (inverse — low confidence = higher risk)
        confidence = node_data.get("confidence", 1.0)
        evidence.append(max(0.0, 1.0 - confidence))
        if confidence < 0.5:
            factors.append("low_confidence")

        # Axis 4: Tags / indicators
        tags = node_data.get("tags", [])
        if isinstance(tags, list):
            tag_risk = min(0.5, len(tags) * 0.1)
            if tag_risk > 0:
                evidence.append(tag_risk)
                factors.append(f"tags:{len(tags)}")

        # Compute combined score
        bayes = BayesRiskModel()
        risk_score = bayes.compute_posterior(
            evidence_scores=evidence,
            entity_type=node_type,
        )

        # Determine risk level
        risk_level = self._classify_risk(risk_score)

        # Estimate connections
        edge_list = graph_state.get("edge_list", [])
        num_conns = sum(
            1 for e in edge_list
            if e.get("source") == node_id or e.get("target") == node_id
        )

        return ScoredEntity(
            target=node_data.get("name", node_id),
            risk_score=risk_score,
            probability=risk_score,
            confidence=1.0 - risk_score,
            risk_level=risk_level,
            contributing_factors=factors,
            prediction_id=str(uuid.uuid4())[:12],
            node_type=node_type,
            graph_centrality=1.0 if node_id in central_nodes else 0.0,
            num_connections=num_conns,
        )

    @staticmethod
    def _classify_risk(score: float) -> str:
        """Map risk score to human-readable level."""
        for level, (lo, hi) in RISK_LEVELS.items():
            if lo <= score < hi:
                return level
        return "negligible"

    @staticmethod
    def aggregate_scores(scores: List[ScoredEntity]) -> Dict[str, Any]:
        """Produce aggregate risk statistics."""
        if not scores:
            return {
                "total_entities_scored": 0,
                "overall_risk": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }

        risk_levels = [s.risk_level for s in scores]
        avg_risk = sum(s.risk_score for s in scores) / len(scores)

        return {
            "total_entities_scored": len(scores),
            "overall_risk": round(avg_risk, 4),
            "critical_count": risk_levels.count("critical"),
            "high_count": risk_levels.count("high"),
            "medium_count": risk_levels.count("medium"),
            "low_count": risk_levels.count("low"),
            "negligible_count": risk_levels.count("negligible"),
            "highest_risk": max(s.risk_score for s in scores) if scores else 0.0,
            "highest_risk_targets": [
                s.target for s in sorted(scores, key=lambda x: x.risk_score, reverse=True)[:5]
            ],
        }


class MonteCarloSimulator:
    """Optional Monte Carlo simulation for risk propagation.

    Simulates 'what-if' scenarios by perturbing risk scores
    and observing cascade effects.
    """

    def __init__(self, iterations: int = 1000):
        self.iterations = iterations

    def simulate_risk_cascade(self, scores: List[ScoredEntity]) -> Dict[str, Any]:
        """Run Monte Carlo simulation to estimate worst-case risk.

        Models risk propagation through connected entities using
        random perturbations of edge weights and scores.
        """
        if len(scores) < 2:
            return {"simulations_run": 0, "message": "insufficient entities"}

        # Extract base scores
        base_scores = {s.target: s.risk_score for s in scores}
        targets = list(base_scores.keys())

        cascade_risk_all = {t: [] for t in targets}

        for _ in range(self.iterations):
            # Perturb each score with Gaussian noise
            perturbed = {}
            for t, score in base_scores.items():
                noise = random.gauss(0, 0.1)
                perturbed[t] = min(max(score + noise, 0.0), 1.0)

            # Simple cascade: propagate through score co-dependence
            for i, t1 in enumerate(targets):
                for j, t2 in enumerate(targets):
                    if i < j:
                        # Mutual influence based on score difference
                        diff = abs(perturbed[t1] - perturbed[t2])
                        influence = (1.0 - diff) * 0.05
                        perturbed[t1] = min(max(perturbed[t1] + influence, 0.0), 1.0)
                        perturbed[t2] = min(max(perturbed[t2] + influence, 0.0), 1.0)

            # Record cascade results
            for t in targets:
                cascade_risk_all[t].append(perturbed[t])

        # Compute statistics
        results = {}
        for t, risks in cascade_risk_all.items():
            mean_risk = sum(risks) / len(risks)
            worst_case = max(risks)
            variance = sum((r - mean_risk) ** 2 for r in risks) / len(risks)
            results[t] = {
                "base_risk": base_scores[t],
                "mean_simulated": round(mean_risk, 4),
                "worst_case": round(worst_case, 4),
                "variance": round(variance, 6),
                "risk_delta": round(mean_risk - base_scores[t], 4),
            }

        return {
            "simulations_run": self.iterations,
            "entity_results": results,
            "max_worst_case": max(
                (r["worst_case"] for r in results.values()), default=0.0
            ),
            "avg_delta": round(
                sum(r["risk_delta"] for r in results.values()) / max(len(results), 1),
                4,
            ),
        }


class ProbabilityEngine:
    """V5: Risk scoring & predictive threat likelihood.

    Input:  Dict[str, Any] graph_state from V4 Graph
    Output: List[Dict] scored predictions → feeds V6, V7, V8
    """

    def __init__(self):
        self.config = get_config()
        self.scorer = RiskScorer()
        self.bayes = BayesRiskModel()
        self.monte_carlo = MonteCarloSimulator(
            iterations=1000 if self.config.v5_probability.enable_monte_carlo else 0
        )

        self._stats: Dict[str, Any] = {
            "total_scored": 0,
            "critical_count": 0,
            "high_count": 0,
            "overall_risk": 0.0,
            "scoring_time_ms": 0.0,
            "monte_carlo_run": False,
        }

    async def score(self, graph_state: Dict[str, Any]) -> list:
        """Score entities in the graph for risk probability.

        Args:
            graph_state: Dict from V4 GraphEngine.build()

        Returns:
            List of serializable scored entity dicts for downstream use.
        """
        start = time.time()
        logger.info("V5 Probability scoring graph state")

        if not graph_state or graph_state.get("status") == "disabled":
            logger.info("  Graph disabled — returning empty scores")
            return []

        node_list = graph_state.get("node_list", [])
        edge_list = graph_state.get("edge_list", [])
        metrics = graph_state.get("metrics", {})

        if not node_list:
            logger.info("  No nodes to score — returning empty")
            return []

        # Score each node
        scored: List[ScoredEntity] = []
        for node in node_list:
            try:
                node_id = node.get("id", "")
                scored_entity = self.scorer.score_node(node_id, node, graph_state)
                scored.append(scored_entity)
            except Exception as e:
                logger.warning("  Error scoring node %s: %s", node.get("id", "?"), e)

        # Sort by risk (highest first)
        scored.sort(key=lambda s: s.risk_score, reverse=True)

        # Aggregate
        agg = self.scorer.aggregate_scores(scored)

        # Optional Monte Carlo
        mc_result = {}
        if self.monte_carlo.iterations > 0 and len(scored) >= 2:
            try:
                mc_result = self.monte_carlo.simulate_risk_cascade(scored)
                self._stats["monte_carlo_run"] = True
                logger.info(
                    "  Monte Carlo: %d simulations, worst_case=%.3f, avg_delta=%.3f",
                    mc_result.get("simulations_run", 0),
                    mc_result.get("max_worst_case", 0),
                    mc_result.get("avg_delta", 0),
                )
            except Exception as e:
                logger.warning("  Monte Carlo simulation failed: %s", e)

        elapsed_ms = (time.time() - start) * 1000
        self._stats.update({
            "total_scored": len(scored),
            "critical_count": agg["critical_count"],
            "high_count": agg["high_count"],
            "overall_risk": agg["overall_risk"],
            "scoring_time_ms": round(elapsed_ms, 2),
        })

        logger.info(
            "V5 complete: %d scored | %d critical | %d high | "
            "overall_risk=%.3f | %.0fms",
            len(scored),
            agg["critical_count"],
            agg["high_count"],
            agg["overall_risk"],
            elapsed_ms,
        )

        # Convert to serializable dicts (downstream consumes list)
        result_list = []
        for s in scored:
            result_list.append({
                "id": s.prediction_id,
                "target": s.target,
                "probability": s.probability,
                "risk": s.risk_score,
                "confidence": s.confidence,
                "risk_level": s.risk_level,
                "prediction_type": s.prediction_type,
                "node_type": s.node_type,
                "contributing_factors": s.contributing_factors,
                "graph_centrality": s.graph_centrality,
                "num_connections": s.num_connections,
            })

        return result_list

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)
