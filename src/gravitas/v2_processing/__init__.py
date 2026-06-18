"""V2: Processing — Normalize, enrich, deduplicate, and classify raw intelligence.

Feeds ProcessedEvent[] into V3 Inference for pattern detection.

DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict

from ..core.config import get_config
from ..models import RawEvent, ProcessedEvent, EventSeverity, IntelligenceEntity

logger = logging.getLogger("gravitas.v2")


# ─── Known patterns for entity extraction ─────────────────────────

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|org|net|edu|gov|mil|io|ai|dev|app|xyz|"
    r"cloud|local|internal|lan|corp|home)\b"
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+")
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,9}", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
PORT_PATTERN = re.compile(r"(?:port|:)\s*(\d{1,5})", re.IGNORECASE)


class EntityExtractor:
    """Extract typed entities from raw text and structured data."""

    def __init__(self):
        self._seen_entities: Set[str] = set()

    def extract_all(self, data: Dict[str, Any]) -> List[IntelligenceEntity]:
        """Extract all known entity types from a data dict."""
        entities: List[IntelligenceEntity] = []
        text_blob = json.dumps(data, default=str)

        # IP addresses
        for ip_str in IP_PATTERN.findall(text_blob):
            if self._is_valid_ip(ip_str):
                eid = f"ip:{ip_str}"
                if eid not in self._seen_entities:
                    self._seen_entities.add(eid)
                    entities.append(IntelligenceEntity(
                        id=eid, type="ip", name=ip_str,
                        properties={"address": ip_str},
                    ))

        # Domains
        for domain in DOMAIN_PATTERN.findall(text_blob):
            eid = f"domain:{domain}"
            if eid not in self._seen_entities:
                self._seen_entities.add(eid)
                entities.append(IntelligenceEntity(
                    id=eid, type="domain", name=domain,
                    properties={"domain": domain},
                ))

        # CVEs
        for cve in CVE_PATTERN.findall(text_blob):
            eid = f"cve:{cve}"
            if eid not in self._seen_entities:
                self._seen_entities.add(eid)
                entities.append(IntelligenceEntity(
                    id=eid, type="vulnerability", name=cve,
                    properties={"cve_id": cve},
                ))

        # Hashes
        for h in HASH_PATTERN.findall(text_blob):
            ht = self._classify_hash(h)
            if ht:
                eid = f"{ht}:{h}"
                if eid not in self._seen_entities:
                    self._seen_entities.add(eid)
                    entities.append(IntelligenceEntity(
                        id=eid, type=ht, name=h[:16],
                        properties={"hash": h, "hash_type": ht},
                    ))

        # Ports (from structured data)
        port_val = data.get("port") or data.get("dst_port") or data.get("src_port")
        if port_val is not None:
            eid = f"port:{port_val}"
            if eid not in self._seen_entities:
                self._seen_entities.add(eid)
                entities.append(IntelligenceEntity(
                    id=eid, type="port", name=str(port_val),
                    properties={"port": int(port_val)},
                ))

        return entities

    @staticmethod
    def _is_valid_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _classify_hash(h: str) -> Optional[str]:
        length = len(h)
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        elif length == 128:
            return "sha512"
        return None

    def reset(self):
        """Clear seen-entity cache (call between pipeline runs)."""
        self._seen_entities.clear()


class Deduplicator:
    """Remove duplicate events based on content fingerprint."""

    def __init__(self):
        self._seen_fingerprints: Set[str] = set()

    def deduplicate(self, events: List[RawEvent]) -> Tuple[List[RawEvent], int]:
        """Return (unique_events, removed_count)."""
        unique: List[RawEvent] = []
        removed = 0
        for ev in events:
            fp = self._fingerprint(ev)
            if fp not in self._seen_fingerprints:
                self._seen_fingerprints.add(fp)
                unique.append(ev)
            else:
                removed += 1
        return unique, removed

    @staticmethod
    def _fingerprint(event: RawEvent) -> str:
        """Create a deterministic fingerprint of an event."""
        raw = json.dumps({
            "source": event.source.value,
            "type": event.event_type,
            "data": event.data,
        }, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def reset(self):
        self._seen_fingerprints.clear()


class DataNormalizer:
    """Normalize event data to a standard schema."""

    COMMON_KEYS = {
        "ip": ["ip", "ip_address", "address", "host", "remote_addr", "client_ip"],
        "port": ["port", "dst_port", "src_port", "remote_port", "local_port"],
        "protocol": ["protocol", "proto", "transport"],
        "user": ["user", "username", "user_name", "login", "account"],
        "hostname": ["hostname", "host_name", "host", "fqdn", "computer_name"],
        "service": ["service", "service_name", "app", "application"],
        "banner": ["banner", "banner_info", "service_banner", "version_info"],
        "os": ["os", "operating_system", "platform"],
    }

    def normalize(self, event: RawEvent) -> ProcessedEvent:
        """Normalize a RawEvent into a structured ProcessedEvent."""
        data = dict(event.data)

        # Strip None values
        normalized = {k: v for k, v in data.items() if v is not None}

        # Normalize common keys to canonical names
        for canonical, aliases in self.COMMON_KEYS.items():
            if canonical not in normalized:
                for alias in aliases:
                    if alias in normalized:
                        normalized[canonical] = normalized.pop(alias)
                        break

        # Type-cast known fields
        if "port" in normalized:
            try:
                normalized["port"] = int(normalized["port"])
            except (ValueError, TypeError):
                pass

        return ProcessedEvent(raw=event, normalized_data=normalized)


class RiskClassifier:
    """Heuristic + ML-based classification of event risk.

    Uses a simple Naive Bayes / scoring classifier (production-ready
    sklearn pipeline) to categorize events as malicious, suspicious,
    or benign.
    """

    # Known malicious indicators (word-level)
    MALICIOUS_INDICATORS = {
        "sql", "drop", "delete", "exec", "eval", "alert(", "<script",
        "../../", "etc/passwd", "union select", "sleep(", "benchmark",
        "root:", "admin:", "/proc/", "/sys/",
    }

    SCORE_THRESHOLDS = {
        "critical": 0.9,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.1,
    }

    def __init__(self):
        self._sklearn_available = False
        self._classifier = None
        self._vectorizer = None
        self._init_ml()

    def _init_ml(self):
        """Initialize sklearn components if available."""
        try:
            from sklearn.feature_extraction.text import HashingVectorizer
            from sklearn.naive_bayes import MultinomialNB

            self._vectorizer = HashingVectorizer(
                n_features=2 ** 10,
                alternate_sign=False,
                analyzer="char_wb",
                ngram_range=(3, 6),
            )
            self._classifier = MultinomialNB(alpha=0.1)

            # Warm up with basic training data
            self._warm_up()
            self._sklearn_available = True
            logger.debug("sklearn classifier initialized")
        except ImportError:
            logger.debug("sklearn not available — using heuristic classifier")
        except Exception as e:
            logger.debug("ML init failed — using heuristics: %s", e)

    def _warm_up(self):
        """Train the classifier on basic benign vs. malicious examples."""
        benign = [
            "GET /index.html HTTP/1.1",
            "POST /api/login HTTP/1.1",
            "DNS query for google.com",
            "SSH connection from 10.0.0.1",
            "HTTPS to 192.168.1.1:443",
            "Ping reply from 8.8.8.8",
            "200 OK response",
            "Directory listing of /var/www",
            "SYN-ACK from server",
        ]
        malicious = [
            "SELECT * FROM users WHERE id=1 OR 1=1",
            "GET /etc/passwd HTTP/1.1",
            "<script>alert('xss')</script>",
            "POST /api/login with SQL injection payload",
            "Port scan of 10.0.0.0/24 on port 445",
            "Brute force SSH attempt from 185.220.101.x",
            "Directory traversal attempt via ../../../etc/shadow",
            "Base64-encoded shell command in URL parameter",
            "Outbound connection to known C2 IP 185.130.5.x:8080",
        ]

        texts = benign + malicious
        labels = [0] * len(benign) + [1] * len(malicious)

        if self._vectorizer and self._classifier:
            X = self._vectorizer.fit_transform(texts)
            self._classifier.fit(X, labels)
            logger.debug("Classifier warmed with %d samples", len(texts))

    def classify(self, event: RawEvent, normalized: Dict[str, Any]) -> float:
        """Return a risk score 0.0–1.0 for the given event."""
        text = self._event_to_text(event, normalized)
        keyword_score = self._keyword_score(text)

        if self._sklearn_available and self._classifier and self._vectorizer:
            try:
                X = self._vectorizer.transform([text])
                proba = self._classifier.predict_proba(X)[0]
                ml_score = proba[1] if len(proba) > 1 else 0.0
                # Blend: 30% keyword, 70% ML
                return 0.3 * keyword_score + 0.7 * ml_score
            except Exception:
                pass

        return keyword_score

    def _keyword_score(self, text: str) -> float:
        """Heuristic score based on known malicious indicators."""
        text_lower = text.lower()
        matches = sum(
            1 for ind in self.MALICIOUS_INDICATORS
            if ind in text_lower
        )
        if matches == 0:
            return 0.0
        # Sigmoid-like mapping
        return min(1.0, matches / (matches + 3))

    @staticmethod
    def _event_to_text(event: RawEvent, normalized: Dict[str, Any]) -> str:
        """Serialize event to text for ML classification."""
        parts = [
            event.event_type,
            event.severity.value,
            json.dumps(normalized, default=str),
        ]
        return " ".join(parts)


class ProcessingEngine:
    """V2: Normalize, enrich, deduplicate, and classify raw intelligence.

    Input:  List[RawEvent] from V1 Ingestion
    Output: List[ProcessedEvent] → feeds V3 Inference
    """

    def __init__(self):
        self.config = get_config()
        self.extractor = EntityExtractor()
        self.dedup = Deduplicator()
        self.normalizer = DataNormalizer()
        self.classifier = RiskClassifier()

        self._stats: Dict[str, Any] = {
            "total_raw": 0,
            "dedup_removed": 0,
            "total_processed": 0,
            "entities_found": 0,
            "avg_risk_score": 0.0,
            "processing_time_ms": 0.0,
        }

    async def process(self, events: List[RawEvent]) -> List[ProcessedEvent]:
        """Process raw events into structured, enriched intelligence.

        Stages:
          1. Deduplication (content fingerprint)
          2. Data normalization (canonical schemas)
          3. Entity extraction (IPs, domains, CVEs, hashes, ports)
          4. Risk scoring (heuristic + optional sklearn ML)
          5. Enrichment tagging
        """
        start = time.time()
        logger.info(
            "V2 Processing %d raw event(s) — dedup, normalize, enrich, classify",
            len(events),
        )

        self._stats["total_raw"] = len(events)
        self.extractor.reset()

        # Stage 1: Deduplicate
        if self.config.v2_processing.deduplicate:
            unique_events, removed = self.dedup.deduplicate(events)
            self._stats["dedup_removed"] = removed
            logger.debug("  Dedup removed %d/%d events", removed, len(events))
        else:
            unique_events = list(events)

        if not unique_events:
            logger.info("  No unique events after dedup — returning empty")
            self._stats["total_processed"] = 0
            return []

        # Stages 2-4: Normalize, extract entities, classify
        processed: List[ProcessedEvent] = []
        total_risk = 0.0

        for raw_event in unique_events:
            try:
                # Normalize
                pe = self.normalizer.normalize(raw_event)

                # Entity extraction
                if self.config.v2_processing.extract_entities:
                    entities = self.extractor.extract_all(pe.normalized_data)
                    pe.entities = [e.id for e in entities]
                    pe.enrichment["entities"] = [e.to_dict() if hasattr(e, 'to_dict') else str(e) for e in entities]
                    self._stats["entities_found"] += len(entities)

                # Risk classification
                risk_score = self.classifier.classify(raw_event, pe.normalized_data)
                pe.confidence = 1.0 - risk_score  # confidence in benign-ness
                pe.enrichment["risk_score"] = round(risk_score, 4)
                pe.enrichment["processing_version"] = "v2.0"

                total_risk += risk_score
                processed.append(pe)

            except Exception as e:
                logger.warning("  Error processing event %s: %s", raw_event.source_id, e)
                # Still include with basic normalization
                pe = ProcessedEvent(raw=raw_event)
                pe.normalized_data = {"error": str(e)}
                pe.enrichment["processing_error"] = str(e)
                processed.append(pe)

        elapsed_ms = (time.time() - start) * 1000
        avg_risk = total_risk / len(processed) if processed else 0.0

        self._stats["total_processed"] = len(processed)
        self._stats["avg_risk_score"] = round(avg_risk, 4)
        self._stats["processing_time_ms"] = round(elapsed_ms, 2)

        logger.info(
            "V2 complete: %d processed | %d entities | avg_risk=%.3f | %.0fms",
            len(processed),
            self._stats["entities_found"],
            avg_risk,
            elapsed_ms,
        )

        return processed

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)
