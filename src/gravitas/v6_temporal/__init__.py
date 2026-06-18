"""V6: Temporal — Time-series analysis, trend prediction, and attack window detection.

Analyzes event timing patterns to predict future activity windows.
Feeds temporal state into V7 Digital Twin.

Input:  List[Prediction] from V3 Inference
Output: Dict[str, Any] temporal state → feeds V7

DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ..core.config import get_config
from ..models import Prediction

logger = logging.getLogger("gravitas.v6")


# ─── Time binning utilities ───────────────────────────────────────

SECONDS_MINUTE = 60
SECONDS_HOUR = 3600
SECONDS_DAY = 86400
SECONDS_WEEK = 604800


def parse_timestamp(ts: Any) -> float:
    """Parse various timestamp formats to Unix epoch seconds."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            # ISO format
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError):
            try:
                # Unix timestamp string
                return float(ts)
            except (ValueError, TypeError):
                return time.time()
    return time.time()


@dataclass
class TimeBin:
    """A time-binned aggregation of events."""
    window_start: float  # epoch seconds
    window_end: float
    event_count: int = 0
    prediction_types: Counter = field(default_factory=Counter)
    avg_probability: float = 0.0


@dataclass
class Trend:
    """A detected trend in temporal data."""
    direction: str  # increasing, decreasing, stable, cyclic
    slope: float = 0.0
    confidence: float = 0.0
    description: str = ""
    bin_count: int = 0
    period_seconds: float = 0.0  # for cyclic trends


@dataclass
class AttackWindow:
    """A predicted window of likely attack activity."""
    start_time: float
    end_time: float
    confidence: float
    expected_event_types: List[str] = field(default_factory=list)
    predicted_intensity: float = 0.0  # 0.0–1.0
    source: str = ""


class TimeBinner:
    """Bin events into time windows for analysis."""

    def __init__(self, window_size: int = 3600):
        self.window_size = window_size  # seconds per bin

    def bin_predictions(self, predictions: List[Prediction]) -> List[TimeBin]:
        """Group predictions into time windows."""
        if not predictions:
            return []

        # Collect timestamps
        timestamps = []
        for pred in predictions:
            ts = parse_timestamp(pred.created_at)
            timestamps.append((ts, pred))

        if not timestamps:
            return []

        # Determine time range
        min_ts = min(ts for ts, _ in timestamps)
        max_ts = max(ts for ts, _ in timestamps)

        # Create bins
        num_bins = max(1, int((max_ts - min_ts) / self.window_size) + 1)
        bins: List[TimeBin] = []

        for i in range(num_bins):
            ws = min_ts + (i * self.window_size)
            we = ws + self.window_size
            bins.append(TimeBin(window_start=ws, window_end=we))

        # Assign predictions to bins
        for ts, pred in timestamps:
            bin_idx = min(
                num_bins - 1,
                max(0, int((ts - min_ts) / self.window_size)),
            )
            bins[bin_idx].event_count += 1
            bins[bin_idx].prediction_types[pred.prediction_type] += 1
            # Running average for probability
            b = bins[bin_idx]
            n = b.event_count
            b.avg_probability = (
                (b.avg_probability * (n - 1) + pred.probability) / n
            )

        return bins


class TrendDetector:
    """Detect trends, periodicity, and direction changes in time-series."""

    def __init__(self):
        pass

    def analyze(self, bins: List[TimeBin]) -> List[Trend]:
        """Analyze binned data for trends."""
        if len(bins) < 3:
            return [Trend(
                direction="stable",
                description="Insufficient data for trend analysis",
                bin_count=len(bins),
            )]

        trends: List[Trend] = []
        counts = [b.event_count for b in bins]

        # Linear regression slope
        n = len(counts)
        x_mean = (n - 1) / 2.0
        y_mean = sum(counts) / n

        numerator = sum((i - x_mean) * (c - y_mean) for i, c in enumerate(counts))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        slope = numerator / max(denominator, 0.001)

        # Correlation coefficient (r)
        std_x = math.sqrt(sum((i - x_mean) ** 2 for i in range(n)) / n)
        std_y = math.sqrt(sum((c - y_mean) ** 2 for c in counts) / n)
        r = numerator / max(n * std_x * std_y, 0.001) if std_x > 0 and std_y > 0 else 0
        r = max(-1.0, min(1.0, r))

        # Determine direction
        abs_r = abs(r)
        if abs_r < 0.3:
            direction = "stable"
            confidence = 1.0 - abs_r
            description = "No significant trend detected"
        elif slope > 0:
            direction = "increasing"
            confidence = abs_r
            change_pct = ((counts[-1] - counts[0]) / max(counts[0], 1)) * 100
            description = (
                f"Activity increasing (slope={slope:.2f}, "
                f"change={change_pct:+.0f}%, r={r:.3f})"
            )
        else:
            direction = "decreasing"
            confidence = abs_r
            change_pct = ((counts[-1] - counts[0]) / max(counts[0], 1)) * 100
            description = (
                f"Activity decreasing (slope={slope:.2f}, "
                f"change={change_pct:+.0f}%, r={r:.3f})"
            )

        trends.append(Trend(
            direction=direction,
            slope=round(slope, 4),
            confidence=round(confidence, 4),
            description=description,
            bin_count=n,
        ))

        # Detect periodicity via simple autocorrelation
        period = self._detect_periodicity(counts)
        if period > 0:
            trends.append(Trend(
                direction="cyclic",
                slope=0.0,
                confidence=0.6,
                description=f"Cyclic pattern detected with period ~{period} bins",
                bin_count=n,
                period_seconds=period * (bins[1].window_start - bins[0].window_start),
            ))

        return trends

    @staticmethod
    def _detect_periodicity(counts: List[int], max_period: int = 12) -> int:
        """Detect periodicity using autocorrelation.

        Returns the period in bins (0 if none detected).
        """
        n = len(counts)
        if n < max_period * 2:
            return 0

        mean = sum(counts) / n
        centered = [c - mean for c in counts]

        best_period = 0
        best_corr = 0.0

        for period in range(2, min(max_period, n // 2)):
            corr = 0.0
            pairs = 0
            for i in range(n - period):
                corr += centered[i] * centered[i + period]
                pairs += 1
            corr = corr / max(pairs, 1)

            # Normalize by variance
            variance = sum(c ** 2 for c in centered) / max(n, 1)
            if variance > 0:
                corr = corr / max(variance, 0.001)

            if corr > best_corr and corr > 0.3:
                best_corr = corr
                best_period = period

        return best_period


class AttackWindowPredictor:
    """Predict future time windows of likely attack activity."""

    def __init__(self, lookahead_windows: int = 6):
        self.lookahead_windows = lookahead_windows

    def predict(self, bins: List[TimeBin], trends: List[Trend],
                predictions: List[Prediction]) -> List[AttackWindow]:
        """Predict future attack windows based on temporal patterns."""
        if not bins or not predictions:
            return []

        windows: List[AttackWindow] = []
        last_bin = bins[-1]
        bin_width = last_bin.window_end - last_bin.window_start

        # Get dominant prediction types from recent activity
        recent_types = bins[-min(3, len(bins)):]
        type_counts: Counter = Counter()
        for rb in recent_types:
            type_counts.update(rb.prediction_types)
        dominant_types = [t for t, _ in type_counts.most_common(3)]

        # Determine trend-based scaling
        trend = trends[0] if trends else Trend(direction="stable")
        if trend.direction == "increasing":
            intensity_mult = 1.0 + min(trend.slope * 2, 0.5)
        elif trend.direction == "decreasing":
            intensity_mult = max(0.1, 1.0 - abs(trend.slope) * 0.5)
        else:
            intensity_mult = 1.0

        # Average event rate
        total_events = sum(b.event_count for b in bins)
        avg_rate = total_events / max(len(bins), 1)

        # Generate forward-looking windows
        for i in range(1, self.lookahead_windows + 1):
            ws = last_bin.window_end + ((i - 1) * bin_width)
            we = ws + bin_width

            # Confidence decays with distance into future
            confidence = max(0.1, 1.0 - (i / self.lookahead_windows))

            # Predicted intensity based on trend + historical rate
            predicted_intensity = min(1.0, (avg_rate / 10) * intensity_mult * confidence)

            windows.append(AttackWindow(
                start_time=ws,
                end_time=we,
                confidence=round(confidence, 4),
                expected_event_types=list(dominant_types),
                predicted_intensity=round(predicted_intensity, 4),
                source="temporal_prediction",
            ))

        return windows


class TemporalEngine:
    """V6: Time-series analysis, trend detection, and attack window prediction.

    Input:  List[Prediction] from V3 Inference
    Output: Dict[str, Any] temporal analysis → feeds V7 Digital Twin
    """

    def __init__(self):
        self.config = get_config()
        window = self.config.v6_temporal.window_size
        self.binner = TimeBinner(window_size=window)
        self.trend_detector = TrendDetector()
        self.window_predictor = AttackWindowPredictor()

        self._stats: Dict[str, Any] = {
            "total_analyzed": 0,
            "bins_created": 0,
            "trends_found": 0,
            "windows_predicted": 0,
            "trend_direction": "",
            "temporal_time_ms": 0.0,
        }

    async def analyze(self, predictions: List[Prediction]) -> Dict[str, Any]:
        """Analyze temporal patterns in event/prediction data.

        Args:
            predictions: List of Prediction objects from V3 Inference.

        Returns:
            Dict with bins, trends, predicted windows, and summary stats.
        """
        start = time.time()
        logger.info(
            "V6 Temporal analyzing %d prediction(s)",
            len(predictions),
        )

        if not predictions:
            logger.info("  No predictions to analyze — returning empty")
            return {
                "bins": [],
                "trends": [],
                "predicted_windows": [],
                "summary": {"total_events": 0, "time_span_hours": 0},
            }

        # Bin events
        bins = self.binner.bin_predictions(predictions)
        self._stats["bins_created"] = len(bins)

        # Detect trends
        trends = self.trend_detector.analyze(bins)
        self._stats["trends_found"] = len(trends)
        if trends:
            self._stats["trend_direction"] = trends[0].direction

        # Predict future windows
        predicted = self.window_predictor.predict(bins, trends, predictions)
        self._stats["windows_predicted"] = len(predicted)

        # Compute time span
        time_span = 0.0
        if bins:
            time_span = (bins[-1].window_end - bins[0].window_start) / SECONDS_HOUR

        elapsed_ms = (time.time() - start) * 1000
        self._stats["total_analyzed"] = len(predictions)
        self._stats["temporal_time_ms"] = round(elapsed_ms, 2)

        # Serialize for output
        result = {
            "bins": [
                {
                    "window_start": b.window_start,
                    "window_end": b.window_end,
                    "event_count": b.event_count,
                    "prediction_types": dict(b.prediction_types),
                    "avg_probability": round(b.avg_probability, 4),
                }
                for b in bins
            ],
            "trends": [
                {
                    "direction": t.direction,
                    "slope": t.slope,
                    "confidence": t.confidence,
                    "description": t.description,
                    "period_seconds": t.period_seconds,
                }
                for t in trends
            ],
            "predicted_windows": [
                {
                    "start_time": w.start_time,
                    "end_time": w.end_time,
                    "confidence": w.confidence,
                    "expected_event_types": w.expected_event_types,
                    "predicted_intensity": w.predicted_intensity,
                    "source": w.source,
                }
                for w in predicted
            ],
            "summary": {
                "total_events": sum(b.event_count for b in bins),
                "time_span_hours": round(time_span, 2),
                "num_bins": len(bins),
                "trend_direction": trends[0].direction if trends else "unknown",
                "windows_predicted": len(predicted),
                "next_window": predicted[0] if predicted else None,
            },
        }

        logger.info(
            "V6 complete: %d bins | %d trends | %d windows predicted | "
            "trend=%s | %.0fms",
            len(bins), len(trends), len(predicted),
            trends[0].direction if trends else "none",
            elapsed_ms,
        )

        return result

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)
