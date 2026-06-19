"""Pipeline orchestrator — runs V1 through V8 in sequence with resilience.

DarkMatter Security — Invisible Influence / Indirect Intelligence.
Part of the OmniGRAVITAS Fusion Platform.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .config import get_config
from ..v1_ingestion import IngestionEngine
from ..v2_processing import ProcessingEngine
from ..v3_inference import InferenceEngine
from ..v4_graph import GraphEngine
from ..v5_probability import ProbabilityEngine
from ..v6_temporal import TemporalEngine
from ..v7_digital_twin import DigitalTwinEngine
from ..v8_autonomous import AutonomousEngine

logger = logging.getLogger("gravitas.pipeline")


class PipelineStageError(Exception):
    """Raised when a pipeline stage fails catastrophically."""
    pass


class GRAVITASPipeline:
    """The full V1-V8 pipeline orchestrator with per-stage resilience.

    Each stage feeds into the next:
        V1 -> V2 -> V3 -> V4 -> V5 -> V6 -> V7 -> V8

    Stages are wrapped in try/except so a single stage failure
    doesn't kill the entire pipeline. Failed stages produce
    empty results and the pipeline continues.

    Data flow:
        V1: RawEvent[]          → V2
        V2: ProcessedEvent[]     → V3, V4 (entities)
        V3: Prediction[]         → V4, V6
        V4: graph_state (dict)   → V5, V7
        V5: scores (list[dict])  → V7, V8
        V6: temporal (dict)      → V7
        V7: twin_state (dict)    → V8 (via V5 context)
        V8: Action[]             ← final output
    """

    def __init__(self):
        self.config = get_config()
        self.v1 = IngestionEngine()
        self.v2 = ProcessingEngine()
        self.v3 = InferenceEngine()
        self.v4 = GraphEngine()
        self.v5 = ProbabilityEngine()
        self.v6 = TemporalEngine()
        self.v7 = DigitalTwinEngine()
        self.v8 = AutonomousEngine()

        self._results: Dict[str, Any] = {}
        """Accumulates results from all stages for downstream use."""

        # Pipeline metadata
        self._pipeline_start: float = 0.0
        self._stage_timings: Dict[str, float] = {}

    async def run_full(self) -> Dict[str, Any]:
        """Run the complete V1-V8 pipeline once with per-stage error handling."""
        self._pipeline_start = time.time()
        self._stage_timings = {}

        # ── Stage Variables ──────────────────────────────────────────
        events: List = []
        processed: List = []
        inferred: List = []
        graph_state: Dict = {}
        scores: List = []
        temporal: Dict = {}
        twin: Dict = {}
        actions: List = []

        logger.info("=" * 62)
        logger.info("  ╔══════════════════════════════════════════════════════╗")
        logger.info("  ║     OMNIGRAVITAS — Full Intelligence Pipeline       ║")
        logger.info("  ║     V1 → V2 → V3 → V4 → V5 → V6 → V7 → V8         ║")
        logger.info("  ╚══════════════════════════════════════════════════════╝")
        logger.info("=" * 62)

        # ── V1: Ingestion ──────────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V1] Data Ingestion — Collecting intelligence")
            ingest_results = await self.v1.run_once()
            events = self.v1.get_buffer()
            logger.info("  ✓ %d event(s) ingested from %d source(s)",
                        len(events), len(ingest_results))
        except Exception as e:
            logger.error("✗ V1 ingestion failed: %s", e)
        self._stage_timings["v1"] = (time.time() - t0) * 1000

        # ── V2: Processing ─────────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V2] Processing — Normalize, enrich, classify")
            if self.config.v2_processing.enabled and events:
                processed = await self.v2.process(events)
            logger.info("  ✓ %d event(s) processed", len(processed))
        except Exception as e:
            logger.error("✗ V2 processing failed: %s", e)
        self._stage_timings["v2"] = (time.time() - t0) * 1000

        # ── V3: Inference ──────────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V3] Inference — Patterns, anomalies, kill chain")
            if self.config.v3_inference.enabled and processed:
                inferred = await self.v3.analyze(processed)
            logger.info("  ✓ %d prediction(s) generated", len(inferred))
        except Exception as e:
            logger.error("✗ V3 inference failed: %s", e)
        self._stage_timings["v3"] = (time.time() - t0) * 1000

        # ── V4: Graph ──────────────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V4] Knowledge Graph — Entities, relationships, paths")
            if self.config.v4_graph.enabled and inferred:
                # Extract entities from V2 processed events for richer graph
                entities = []
                for pe in processed:
                    if hasattr(pe, 'enrichment') and pe.enrichment:
                        raw_entities = pe.enrichment.get("entities", [])
                        for e in raw_entities:
                            if isinstance(e, dict):
                                from ..models import IntelligenceEntity
                                try:
                                    entities.append(IntelligenceEntity(**e))
                                except Exception:
                                    pass
                graph_state = await self.v4.build(inferred, entities=entities or None)
            logger.info("  ✓ Graph: %d nodes, %d edges",
                        graph_state.get("nodes", 0), graph_state.get("edges", 0))
        except Exception as e:
            logger.error("✗ V4 graph build failed: %s", e)
        self._stage_timings["v4"] = (time.time() - t0) * 1000

        # ── V5: Probability ────────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V5] Probability — Bayesian risk scoring")
            if self.config.v5_probability.enabled and graph_state:
                scores = await self.v5.score(graph_state)
            logger.info("  ✓ %d entit(ies) scored", len(scores))
        except Exception as e:
            logger.error("✗ V5 probability scoring failed: %s", e)
        self._stage_timings["v5"] = (time.time() - t0) * 1000

        # ── V6: Temporal ───────────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V6] Temporal — Time-series & attack windows")
            if self.config.v6_temporal.enabled and inferred:
                temporal = await self.v6.analyze(inferred)
            logger.info("  ✓ %d bins, %d windows predicted",
                        temporal.get("summary", {}).get("num_bins", 0),
                        temporal.get("summary", {}).get("windows_predicted", 0))
        except Exception as e:
            logger.error("✗ V6 temporal analysis failed: %s", e)
        self._stage_timings["v6"] = (time.time() - t0) * 1000

        # ── V7: Digital Twin ───────────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V7] Digital Twin — State mirroring & simulation")
            if self.config.v7_digital_twin.enabled:
                twin = await self.v7.sync({
                    "scores": scores,
                    "temporal": temporal,
                    "graph": graph_state,
                })
            # entities may be int (count) or dict — handle both
            _e = twin.get("entities", {}) if isinstance(twin, dict) else {}
            _entity_count = len(_e) if isinstance(_e, (dict, list, str)) else int(_e)
            logger.info("  ✓ %d entities, health=%.2f",
                        _entity_count,
                        twin.get("overall_health", 0) if isinstance(twin, dict) else 0)
        except Exception as e:
            logger.error("✗ V7 digital twin sync failed: %s", e)
        self._stage_timings["v7"] = (time.time() - t0) * 1000

        # ── V8: Autonomous Engine ──────────────────────────────────────
        t0 = time.time()
        try:
            logger.info("[V8] Autonomous Engine — Self-acting defense")
            if self.config.v8_autonomous.enabled and scores:
                actions = await self.v8.decide(scores)
            logger.info("  ✓ %d action(s) issued", len(actions))
        except Exception as e:
            logger.error("✗ V8 autonomous decision failed: %s", e)
        self._stage_timings["v8"] = (time.time() - t0) * 1000

        # ── Pipeline Summary ──────────────────────────────────────────
        elapsed = time.time() - self._pipeline_start

        logger.info("=" * 62)
        logger.info("  PIPELINE COMPLETE — %.2fs total", elapsed)
        logger.info("─" * 62)
        logger.info("  V1  Ingestion    │ %4d events  │ %6.0fms",
                    len(events), self._stage_timings.get("v1", 0))
        logger.info("  V2  Processing   │ %4d events  │ %6.0fms",
                    len(processed), self._stage_timings.get("v2", 0))
        logger.info("  V3  Inference    │ %4d preds   │ %6.0fms",
                    len(inferred), self._stage_timings.get("v3", 0))
        logger.info("  V4  Graph        │ %4d nodes   │ %6.0fms",
                    graph_state.get("nodes", 0), self._stage_timings.get("v4", 0))
        logger.info("  V5  Probability  │ %4d scores  │ %6.0fms",
                    len(scores), self._stage_timings.get("v5", 0))
        logger.info("  V6  Temporal     │ %4d bins    │ %6.0fms",
                    temporal.get("summary", {}).get("num_bins", 0),
                    self._stage_timings.get("v6", 0))
        logger.info("  V7  Digital Twin │ %4d ents    │ %6.0fms",
                    len(twin.get("entities", {})) if isinstance(twin.get("entities", {}), (dict, list, str)) else int(twin.get("entities", 0)),
                    self._stage_timings.get("v7", 0))
        logger.info("  V8  Autonomous   │ %4d actions │ %6.0fms",
                    len(actions), self._stage_timings.get("v8", 0))
        logger.info("=" * 62)

        self._results = {
            "pipeline_complete": True,
            "duration_seconds": round(elapsed, 2),
            "stage_timings_ms": self._stage_timings,
            "events": len(events),
            "processed": len(processed),
            "inferred": len(inferred),
            "graph_nodes": graph_state.get("nodes", 0) if isinstance(graph_state, dict) else 0,
            "graph_edges": graph_state.get("edges", 0) if isinstance(graph_state, dict) else 0,
            "scores": len(scores),
            "temporal_bins": temporal.get("summary", {}).get("num_bins", 0) if isinstance(temporal, dict) else 0,
            "twin_entities": len(twin.get("entities", {})) if isinstance(twin.get("entities", {}), (dict, list, str)) else int(twin.get("entities", 0)),
            "twin_health": twin.get("overall_health", 0) if isinstance(twin, dict) else 0,
            "actions": len(actions),
        }
        return self._results

    @property
    def results(self) -> Dict[str, Any]:
        return self._results


def run_pipeline():
    """CLI entry point for full pipeline."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    pipeline = GRAVITASPipeline()
    result = asyncio.run(pipeline.run_full())
    
    # Print final summary to stdout
    print(f"\n{'=' * 62}")
    print(f"  OmniGRAVITAS — DarkMatter Security")
    print(f"  Pipeline complete in {result.get('duration_seconds', 0):.2f}s")
    print(f"  Events: {result.get('events', 0)} | "
          f"Scores: {result.get('scores', 0)} | "
          f"Actions: {result.get('actions', 0)}")
    print(f"  Health: {result.get('twin_health', 0):.2%}")
    print(f"{'=' * 62}\n")
