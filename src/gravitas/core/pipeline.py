"""Pipeline orchestrator - runs V1 through V8 in sequence."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import get_config
from ..v1_ingestion import IngestionEngine
from ..v2_processing import ProcessingEngine
from ..v3_inference import InferenceEngine
from ..v4_graph import GraphEngine
from ..v5_probability import ProbabilityEngine
from ..v6_temporal import TemporalEngine
from ..v7_digital_twin import DigitalTwinEngine
from ..v8_autonomous import AutonomousEngine


class GRAVITASPipeline:
    """The full V1-V8 pipeline orchestrator.

    Each stage feeds into the next:
    V1 -> V2 -> V3 -> V4 -> V5 -> V6 -> V7 -> V8
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

    async def run_full(self) -> Dict[str, Any]:
        """Run the complete V1-V8 pipeline once."""
        start = time.time()
        print("\n" + "=" * 60)
        print("  GRAVITAS - Full Pipeline V1-V8")
        print("=" * 60)

        # V1: Ingest
        print("\n  [V1] Data Ingestion")
        ingest_results = await self.v1.run_once()
        events = self.v1.get_buffer()
        print(f"       -> {len(events)} events ingested")

        # V2: Process
        print("\n  [V2] Processing")
        processed = await self.v2.process(events)
        print(f"       -> {len(processed)} events processed")

        # V3: Infer
        print("\n  [V3] Inference")
        inferred = await self.v3.analyze(processed)
        print(f"       -> {len(inferred)} events analyzed")

        # V4: Graph
        print("\n  [V4] Knowledge Graph")
        graph_state = await self.v4.build(inferred)
        print(f"       -> {graph_state}")

        # V5: Probability
        print("\n  [V5] Probability & Risk")
        scores = await self.v5.score(graph_state)
        print(f"       -> {len(scores)} risk scores")

        # V6: Temporal
        print("\n  [V6] Temporal Analysis")
        temporal = await self.v6.analyze(inferred)
        print(f"       -> {temporal}")

        # V7: Digital Twin
        print("\n  [V7] Digital Twin")
        twin = await self.v7.sync({"scores": scores, "temporal": temporal})
        print(f"       -> {twin}")

        # V8: Act
        print("\n  [V8] Autonomous Engine")
        actions = await self.v8.decide(scores)
        print(f"       -> {len(actions)} actions decided")

        elapsed = time.time() - start
        print(f"\n{'=' * 60}")
        print(f"  PIPELINE COMPLETE - {elapsed:.2f}s")
        print(f"{'=' * 60}\n")

        return {
            "events": len(events),
            "processed": len(processed),
            "actions": len(actions),
            "duration": round(elapsed, 2),
        }


def run_pipeline():
    """CLI entry point for full pipeline."""
    import asyncio
    pipeline = GRAVITASPipeline()
    asyncio.run(pipeline.run_full())
