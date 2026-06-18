"""V3: Inference — Pattern recognition, anomaly detection, and attack-chain analysis.

Feeds Prediction[] into V4 Graph and V6 Temporal.

Input:  List[ProcessedEvent] from V2 Processing
Output: List[Prediction]

DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from ..core.config import get_config
from ..models import ProcessedEvent, Prediction, EventSeverity

logger = logging.getLogger("gravitas.v3")


# ─── Attack pattern definitions ───────────────────────────────────

@dataclass
class AttackPattern:
    """A known attack pattern signature."""
    name: str
    description: str
    mitre_id: str = ""
    kill_chain_phase: str = ""  # recon, weaponize, deliver, exploit, c2, exfil
    indicators: List[str] = field(default_factory=list)
    min_matches: int = 2
    weight: float = 1.0


# Built-in pattern library
BUILTIN_PATTERNS: List[AttackPattern] = [
    AttackPattern(
        name="Port Scan",
        description="Sequential or random port scanning activity",
        mitre_id="T1046",
        kill_chain_phase="recon",
        indicators=["scan", "port", "syn", "tcp connect", "nmap"],
        min_matches=1,
        weight=0.6,
    ),
    AttackPattern(
        name="Brute Force Attack",
        description="Repeated authentication attempts",
        mitre_id="T1110",
        kill_chain_phase="exploit",
        indicators=["brute", "login", "auth", "password", "ssh auth", "failed"],
        min_matches=2,
        weight=0.8,
    ),
    AttackPattern(
        name="SQL Injection",
        description="SQL injection attempt in query parameters",
        mitre_id="T1190",
        kill_chain_phase="exploit",
        indicators=["sql", "select", "drop ", "union", "or 1=1", "' or", "sqlmap"],
        min_matches=1,
        weight=0.9,
    ),
    AttackPattern(
        name="Directory Traversal",
        description="Path traversal attempts on web resources",
        mitre_id="T1190",
        kill_chain_phase="exploit",
        indicators=["../", "..\\", "etc/passwd", "windows\\system32", "file://"],
        min_matches=1,
        weight=0.85,
    ),
    AttackPattern(
        name="XSS Attempt",
        description="Cross-site scripting payload delivery",
        mitre_id="T1059.007",
        kill_chain_phase="deliver",
        indicators=["<script", "alert(", "onerror=", "onload=", "javascript:"],
        min_matches=1,
        weight=0.75,
    ),
    AttackPattern(
        name="C2 Beaconing",
        description="Periodic outbound connections to suspicious destinations",
        mitre_id="T1071",
        kill_chain_phase="c2",
        indicators=["beacon", "c2", "callback", "reverse shell", "meterpreter"],
        min_matches=1,
        weight=0.95,
    ),
    AttackPattern(
        name="Data Exfiltration",
        description="Large outbound data transfers or unusual egress patterns",
        mitre_id="T1048",
        kill_chain_phase="exfil",
        indicators=["exfil", "dns tunnel", "large upload", "base64", "encoded"],
        min_matches=1,
        weight=0.9,
    ),
    AttackPattern(
        name="Reconnaissance",
        description="Information gathering — DNS, WHOIS, directory enumeration",
        mitre_id="T1595",
        kill_chain_phase="recon",
        indicators=["recon", "whois", "dns", "enumeration", "gobuster", "dirb"],
        min_matches=1,
        weight=0.5,
    ),
]


class PatternMatcher:
    """Match events against known attack patterns."""

    def __init__(self, patterns: Optional[List[AttackPattern]] = None):
        self.patterns = patterns or BUILTIN_PATTERNS

    def match(self, event: ProcessedEvent) -> List[Tuple[AttackPattern, float]]:
        """Return list of (pattern, match_score) tuples for an event."""
        text = self._event_text(event).lower()
        matches: List[Tuple[AttackPattern, float]] = []

        for pattern in self.patterns:
            hit_count = sum(
                1 for ind in pattern.indicators
                if ind.lower() in text
            )
            if hit_count >= pattern.min_matches:
                # Score: fraction of indicators matched × pattern weight
                score = (hit_count / max(len(pattern.indicators), 1)) * pattern.weight
                matches.append((pattern, round(min(score, 1.0), 4)))

        return matches

    @staticmethod
    def _event_text(event: ProcessedEvent) -> str:
        """Serialize event to searchable text."""
        parts = [
            event.raw.event_type,
            event.raw.severity.value,
            json.dumps(event.normalized_data, default=str),
            json.dumps(event.enrichment, default=str),
        ]
        return " ".join(parts)


class AnomalyScorer:
    """Score events for anomalousness based on baselines.

    Maintains statistical baselines of event types, sources,
    and frequencies. Events deviating from baseline get
    higher anomaly scores.
    """

    def __init__(self, decay: float = 0.95):
        self.decay = decay  # Per-cycle decay for baseline adaptation
        self._event_type_counts: Counter = Counter()
        self._source_counts: Counter = Counter()
        self._severity_counts: Counter = Counter()
        self._total_observed: int = 0
        self._cycle: int = 0

    def score(self, event: ProcessedEvent) -> float:
        """Return anomaly score 0.0–1.0 for this event."""
        self._cycle += 1
        scores: List[float] = []

        # Type rarity: uncommon event types score higher
        etype = event.raw.event_type
        type_count = self._event_type_counts.get(etype, 0)
        if type_count > 0:
            type_freq = type_count / max(self._total_observed, 1)
            # Rare types (appearing < 5% of time) are anomalous
            scores.append(max(0.0, 1.0 - (type_freq / 0.05)))
        else:
            # Never-before-seen type → highly anomalous
            scores.append(0.8)

        # Severity rarity
        sev = event.raw.severity.value
        sev_count = self._severity_counts.get(sev, 0)
        if sev_count > 0 and self._total_observed > 0:
            sev_freq = sev_count / self._total_observed
            if sev in ("critical", "high"):
                # Critical/high are always somewhat anomalous
                scores.append(min(1.0, 0.5 + sev_freq))
            else:
                scores.append(max(0.0, 1.0 - (sev_freq / 0.1)))
        else:
            scores.append(0.3)

        # Update baselines
        self._event_type_counts[etype] += 1
        self._source_counts[event.raw.source.value] += 1
        self._severity_counts[sev] += 1
        self._total_observed += 1

        # Decay old baseline influence
        if self._cycle % 100 == 0:
            self._decay_baselines()

        return round(sum(scores) / len(scores), 4)

    def _decay_baselines(self):
        """Apply exponential decay to baseline counters."""
        for counter in (self._event_type_counts, self._source_counts, self._severity_counts):
            for k in list(counter.keys()):
                counter[k] = int(counter[k] * self.decay)
                if counter[k] < 1:
                    del counter[k]

    @property
    def baseline_stats(self) -> Dict[str, Any]:
        return {
            "total_observed": self._total_observed,
            "unique_types": len(self._event_type_counts),
            "cycle": self._cycle,
        }


class KillChainAnalyzer:
    """Reconstruct attack kill chains by correlating related events.

    Maps events to MITRE ATT&CK phases and builds
    attack-chain narratives.
    """

    KILL_CHAIN_PHASES = [
        "recon", "weaponize", "deliver", "exploit", "c2", "exfil"
    ]

    def __init__(self):
        # Active chains by correlation_id / target
        self._active_chains: Dict[str, Dict[str, Any]] = {}

    def analyze(self, predictions: List[Prediction]) -> List[Dict[str, Any]]:
        """Group predictions into kill-chain narratives."""
        chains: Dict[str, Dict[str, Any]] = {}

        for pred in predictions:
            target = pred.target or pred.affected_entities[0] if pred.affected_entities else "unknown"
            chain_key = target

            if chain_key not in chains:
                chains[chain_key] = {
                    "target": target,
                    "phases_detected": set(),
                    "predictions": [],
                    "kill_chain_coverage": 0.0,
                    "highest_confidence": 0.0,
                }

            chains[chain_key]["phases_detected"].add(pred.prediction_type)
            chains[chain_key]["predictions"].append(pred)
            chains[chain_key]["highest_confidence"] = max(
                chains[chain_key]["highest_confidence"],
                pred.confidence,
            )

        # Compute kill chain coverage
        result = []
        for chain in chains.values():
            chain["phases_detected"] = sorted(chain["phases_detected"])
            matched_phases = sum(
                1 for p in self.KILL_CHAIN_PHASES
                if p in chain["phases_detected"]
            )
            chain["kill_chain_coverage"] = round(
                matched_phases / len(self.KILL_CHAIN_PHASES), 4
            )
            chain["prediction_count"] = len(chain["predictions"])
            chain["is_full_kill_chain"] = chain["kill_chain_coverage"] >= 0.8

            result.append(chain)

        result.sort(key=lambda c: c["kill_chain_coverage"], reverse=True)
        return result


class InferenceEngine:
    """V3: Pattern recognition, anomaly detection, and kill-chain analysis.

    Input:  List[ProcessedEvent] from V2 Processing
    Output: List[Prediction] → feeds V4 Graph, V6 Temporal, and report generation
    """

    def __init__(self):
        self.config = get_config()
        self.pattern_matcher = PatternMatcher()
        self.anomaly_scorer = AnomalyScorer()
        self.kill_chain = KillChainAnalyzer()

        self._stats: Dict[str, Any] = {
            "total_processed": 0,
            "patterns_matched": 0,
            "predictions_generated": 0,
            "anomalies_detected": 0,
            "kill_chains_found": 0,
            "full_kill_chains": 0,
            "inference_time_ms": 0.0,
        }

    async def analyze(self, events: List[ProcessedEvent]) -> List[Prediction]:
        """Analyze processed events for patterns, anomalies, and threats.

        Returns a list of Prediction objects with:
          - Matched attack patterns
          - Anomaly scores above threshold
          - Attack-chain phase mapping
          - Confidence and probability estimates
        """
        start = time.time()
        logger.info(
            "V3 Inference analyzing %d processed event(s)",
            len(events),
        )

        if not events:
            logger.info("  No events to analyze — returning empty")
            return []

        predictions: List[Prediction] = []
        pattern_hits = 0
        anomaly_hits = 0

        for event in events:
            try:
                # Pattern matching
                pattern_matches = self.pattern_matcher.match(event)

                # Anomaly scoring
                anomaly_score = self.anomaly_scorer.score(event)

                # Generate predictions
                for pattern, match_score in pattern_matches:
                    risk = max(match_score, anomaly_score)
                    pred = Prediction(
                        id=str(uuid.uuid4())[:12],
                        target=event.normalized_data.get("ip", event.raw.source_id),
                        prediction_type=pattern.kill_chain_phase or "unknown",
                        probability=round(match_score, 4),
                        time_horizon=self._estimate_horizon(pattern.kill_chain_phase),
                        affected_entities=event.entities[:5],
                        suggested_actions=self._suggest_actions(pattern),
                        confidence=round(1.0 - anomaly_score, 4),
                    )
                    predictions.append(pred)
                    pattern_hits += 1

                    logger.debug(
                        "  Pattern match: %s on %s (score=%.3f, anomaly=%.3f)",
                        pattern.name,
                        pred.target,
                        match_score,
                        anomaly_score,
                    )

                # High anomaly without pattern match → generic anomaly prediction
                if anomaly_score > 0.7 and not pattern_matches:
                    pred = Prediction(
                        id=str(uuid.uuid4())[:12],
                        target=event.normalized_data.get("ip", event.raw.source_id),
                        prediction_type="anomaly",
                        probability=round(anomaly_score, 4),
                        time_horizon="immediate",
                        affected_entities=event.entities[:3],
                        suggested_actions=["investigate", "log", "alert"],
                        confidence=round(1.0 - anomaly_score / 2, 4),
                    )
                    predictions.append(pred)
                    anomaly_hits += 1

            except Exception as e:
                logger.warning("  Error analyzing event %s: %s", event.raw.source_id, e)

        # Kill-chain analysis across all predictions
        chains = self.kill_chain.analyze(predictions)
        full_chains = [c for c in chains if c.get("is_full_kill_chain")]

        self._stats["total_processed"] = len(events)
        self._stats["patterns_matched"] = pattern_hits
        self._stats["predictions_generated"] = len(predictions)
        self._stats["anomalies_detected"] = anomaly_hits
        self._stats["kill_chains_found"] = len(chains)
        self._stats["full_kill_chains"] = len(full_chains)
        self._stats["inference_time_ms"] = round((time.time() - start) * 1000, 2)

        # Annotate predictions with chain context where applicable
        if chains:
            chain_map = {c["target"]: c for c in chains}
            for pred in predictions:
                chain = chain_map.get(pred.target) or chain_map.get(
                    pred.affected_entities[0] if pred.affected_entities else ""
                )
                if chain:
                    pred.suggested_actions.append(
                        f"kill_chain:{chain['kill_chain_coverage']}:phases:"
                        f"{','.join(chain['phases_detected'])}"
                    )

        logger.info(
            "V3 complete: %d predictions | %d patterns | %d anomalies | "
            "%d chains (%d full) | %.0fms",
            len(predictions),
            pattern_hits,
            anomaly_hits,
            len(chains),
            len(full_chains),
            self._stats["inference_time_ms"],
        )

        return predictions

    @staticmethod
    def _estimate_horizon(kill_chain_phase: str) -> str:
        """Map kill-chain phase to time horizon."""
        if kill_chain_phase in ("recon", "weaponize"):
            return "long_term"
        elif kill_chain_phase in ("deliver",):
            return "medium_term"
        elif kill_chain_phase in ("exploit",):
            return "short_term"
        elif kill_chain_phase in ("c2", "exfil"):
            return "immediate"
        return "medium_term"

    @staticmethod
    def _suggest_actions(pattern: AttackPattern) -> List[str]:
        """Suggest defensive actions for a given pattern."""
        suggestions = {
            "recon": ["block scanner IP", "increase logging", "rate-limit requests"],
            "exploit": ["WAF block", "patch vulnerability", "RASP alert"],
            "deliver": ["sandbox analysis", "email filter", "DLP check"],
            "c2": ["block outbound", "DNS sinkhole", "NGFW block"],
            "exfil": ["DLP alert", "block egress", "traffic capture"],
        }
        return suggestions.get(pattern.kill_chain_phase, ["alert", "investigate"])

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)
