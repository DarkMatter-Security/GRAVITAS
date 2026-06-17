"""V1: Data Ingestion — Collect intelligence from all sources.

The foundation of GRAVITAS. Every prediction, every digital twin,
every autonomous action starts with DATA.

Sources:
  - File system watcher (logs, reports, CSVs)
  - API connectors (REST, WebSocket)
  - OmniPentestX database (existing session data)
  - Network streams (future)
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field

from ..core.config import get_config
from ..models import RawEvent, EventSource, EventSeverity


@dataclass
class IngestionResult:
    """Result of an ingestion cycle."""
    source: str
    events_ingested: int = 0
    events_failed: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def summary(self) -> str:
        status = "[OK]" if self.events_failed == 0 else "[WARN]"
        return f"{status} {self.source}: {self.events_ingested} events ({self.duration_seconds:.2f}s)"


class BaseCollector:
    """Base class for all data collectors."""

    def __init__(self):
        self.config = get_config()
        self._running = False

    async def collect(self) -> List[RawEvent]:
        """Collect data from source. Override in subclasses."""
        raise NotImplementedError

    async def start(self):
        """Start continuous collection."""
        self._running = True

    async def stop(self):
        """Stop continuous collection."""
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @staticmethod
    def _now() -> str:
        return datetime.utcnow().isoformat()


class FileCollector(BaseCollector):
    """Collect data from files: JSON, CSV, logs, reports."""

    def __init__(self, watch_dirs: Optional[List[str]] = None):
        super().__init__()
        self.watch_dirs = watch_dirs or self.config.v1_ingestion.file_watch_dirs
        self._seen_files: Set[str] = set()

    async def collect(self) -> List[RawEvent]:
        events = []
        for dir_path in self.watch_dirs:
            path = Path(dir_path)
            if not path.exists():
                continue
            for file_path in path.glob("**/*"):
                if not file_path.is_file():
                    continue
                file_key = str(file_path.absolute())
                if file_key in self._seen_files:
                    continue
                self._seen_files.add(file_key)
                try:
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                    events.append(RawEvent(
                        source=EventSource.FILE,
                        source_id=file_key,
                        event_type=f"file:{file_path.suffix}",
                        severity=EventSeverity.INFO,
                        data={
                            "path": file_key,
                            "filename": file_path.name,
                            "extension": file_path.suffix,
                            "size": file_path.stat().st_size,
                            "content_preview": content[:1000],
                        },
                        timestamp=self._now(),
                    ))
                except Exception as e:
                    print(f"  [WARN] FileCollector error: {e}")
        return events


class APICollector(BaseCollector):
    """Collect data from REST APIs."""

    def __init__(self, endpoints: Optional[Dict[str, str]] = None):
        super().__init__()
        self.endpoints = endpoints or {}

    async def collect(self) -> List[RawEvent]:
        import aiohttp
        events = []
        async with aiohttp.ClientSession() as session:
            for name, url in self.endpoints.items():
                try:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            events.append(RawEvent(
                                source=EventSource.API,
                                source_id=url,
                                event_type=f"api:{name}",
                                severity=EventSeverity.INFO,
                                data={"endpoint": name, "url": url, "response": data},
                                timestamp=self._now(),
                            ))
                except Exception as e:
                    print(f"  [WARN] APICollector {name}: {e}")
        return events


class OmniPentestXCollector(BaseCollector):
    """Collect data from OmniPentestX database — YOUR other platform.

    This is the bridge between offense (OmniPentestX) and intelligence (GRAVITAS).
    """

    async def collect(self) -> List[RawEvent]:
        events = []
        db_path = Path(self.config.v1_ingestion.omnipentestx_db_path)
        
        if not db_path.exists():
            print("  [WARN] OmniPentestX DB not found - skipping")
            return events

        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check what tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row["name"] for row in cursor.fetchall()]
            print(f"  [DB] OmniPentestX tables: {tables}")

            # Extract sessions
            if "sessions" in tables:
                cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT 50")
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    events.append(RawEvent(
                        source=EventSource.OMNIPENTESTX,
                        source_id=f"session:{row_dict.get('id', 'unknown')}",
                        event_type="session",
                        severity=EventSeverity.INFO,
                        data=row_dict,
                        timestamp=row_dict.get("created_at", self._now()),
                    ))

            # Extract findings
            if "findings" in tables:
                cursor.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT 200")
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    severity = row_dict.get("severity", "info").lower()
                    events.append(RawEvent(
                        source=EventSource.OMNIPENTESTX,
                        source_id=f"finding:{row_dict.get('id', 'unknown')}",
                        event_type="finding",
                        severity=EventSeverity.from_string(severity),
                        data=row_dict,
                        timestamp=row_dict.get("created_at", self._now()),
                    ))

            conn.close()
            sessions = len([e for e in events if e.event_type == 'session'])
            findings = len([e for e in events if e.event_type != 'session'])
            print(f"  [OK] Pulled {sessions} sessions, {findings} findings")

        except Exception as e:
            msg = str(e).encode('ascii', errors='replace').decode('ascii')
            print(f"  [WARN] OmniPentestX DB error: {msg}")

        return events


class IngestionEngine:
    """V1: The Data Ingestion Engine — orchestrates all collectors."""

    def __init__(self):
        self.config = get_config()
        self.collectors: Dict[str, BaseCollector] = {}
        self._register_defaults()
        self._event_buffer: List[RawEvent] = []

    def _register_defaults(self):
        """Register default collectors based on config."""
        if "file" in self.config.v1_ingestion.sources:
            self.collectors["file"] = FileCollector()
        if "api" in self.config.v1_ingestion.sources:
            self.collectors["api"] = APICollector()
        if "omnipentestx" in self.config.v1_ingestion.sources:
            self.collectors["omnipentestx"] = OmniPentestXCollector()

    def register_collector(self, name: str, collector: BaseCollector):
        """Register a custom collector."""
        self.collectors[name] = collector

    async def run_once(self) -> List[IngestionResult]:
        """Run a single ingestion cycle across all collectors."""
        results = []

        for name, collector in self.collectors.items():
            start = time.time()
            try:
                events = await collector.collect()
                elapsed = time.time() - start
                self._event_buffer.extend(events)

                result = IngestionResult(
                    source=name,
                    events_ingested=len(events),
                    duration_seconds=round(elapsed, 3),
                )
                results.append(result)
                print(f"  {result.summary()}")

            except Exception as e:
                elapsed = time.time() - start
                results.append(IngestionResult(
                    source=name,
                    events_failed=1,
                    errors=[str(e)],
                    duration_seconds=round(elapsed, 3),
                ))
                msg = str(e).encode('ascii', errors='replace').decode('ascii')
                print(f"  [FAIL] {name} failed: {msg}")

        return results

    async def run_continuous(self, interval: Optional[int] = None):
        """Run ingestion on a loop."""
        interval = interval or self.config.v1_ingestion.poll_interval
        print(f"  [LOOP] Continuous ingestion every {interval}s - Ctrl+C to stop")

        try:
            while True:
                results = await self.run_once()
                total = sum(r.events_ingested for r in results)
                print(f"  [BUF] Buffer: {len(self._event_buffer)} events total\n")
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print("\n  [STOP] Ingestion stopped")

    def get_buffer(self) -> List[RawEvent]:
        """Get and clear the event buffer for downstream phases."""
        events = list(self._event_buffer)
        self._event_buffer.clear()
        return events

    @property
    def buffer_size(self) -> int:
        return len(self._event_buffer)


def run_ingestion():
    """CLI entry point for V1 ingestion."""
    import asyncio

    print("\n" + "=" * 60)
    print("  GRAVITAS V1 — Data Ingestion Engine")
    print("=" * 60)

    engine = IngestionEngine()
    print(f"\n  Collectors: {list(engine.collectors.keys())}")
    print(f"  Buffer limit: {engine.config.v1_ingestion.max_batch_size}")
    print()

    asyncio.run(engine.run_once())
    
    buffer = engine.get_buffer()
    print(f"\n{'=' * 60}")
    print(f"  V1 COMPLETE — {len(buffer)} events ingested")
    print(f"{'=' * 60}\n")
