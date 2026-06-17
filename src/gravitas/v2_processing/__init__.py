"""V2: Processing — Normalize, enrich, and structure raw data."""

from ..core.config import get_config
from ..models import ProcessedEvent, RawEvent


class ProcessingEngine:
    """V2: Normalize, enrich, and structure raw data."""

    def __init__(self):
        self.config = get_config()

    async def process(self, events: list) -> list[ProcessedEvent]:
        """Process raw events into structured, enriched intelligence."""
        processed = []
        for event in events:
            pe = ProcessedEvent(raw=event)
            # Normalize: standardize fields, remove noise
            pe.normalized_data = self._normalize(event.data)
            # Extract basic entities
            pe.entities = self._extract_entities(event)
            processed.append(pe)
        return processed

    def _normalize(self, data: dict) -> dict:
        """Normalize data to standard format."""
        # Remove None values, standardize keys
        return {k: v for k, v in data.items() if v is not None}

    def _extract_entities(self, event: RawEvent) -> list:
        """Extract basic entities from event data."""
        entities = []
        data = event.data
        # IP addresses
        if "ip" in data:
            entities.append(f"ip:{data['ip']}")
        if "target" in data:
            entities.append(f"target:{data['target']}")
        return entities
