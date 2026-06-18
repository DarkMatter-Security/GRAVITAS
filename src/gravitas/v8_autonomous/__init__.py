"""V8: Autonomous Engine — Self-acting defense & deception deployment.

When risk probability exceeds thresholds, the engine acts autonomously:
  0.8+  → ISOLATE + DEPLOY DECOY (critical)
  0.6+  → MONITOR + ALERT       (high)
  0.3+  → LOG + ANALYZE         (medium)
  <0.3  → NO ACTION             (low)

THIS IS THE ENDGAME of the GRAVITAS pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from ..core.config import get_config


logger = logging.getLogger("gravitas.v8")


@dataclass
class Action:
    """A decision/action produced by the autonomous engine."""
    type: str  # isolate, monitor, alert, deploy_decoy, log, block, report
    target: str
    risk_score: float
    description: str
    priority: str = "medium"  # critical, high, medium, low
    prediction_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "target": self.target,
            "risk_score": self.risk_score,
            "description": self.description,
            "priority": self.priority,
            "prediction_id": self.prediction_id,
        }


def _extract(pred: Union[Dict[str, Any], Any], key: str, default: Any = 0) -> Any:
    """Safely extract an attribute from either a dict or any object."""
    if isinstance(pred, dict):
        return pred.get(key, default)
    return getattr(pred, key, default)


class AutonomousEngine:
    """V8: Self-acting defense & deception deployment.

    Evaluates predictions from V5 Probability Engine and issues
    defensive/offensive actions. Can feed back into OmniPentestX.
    """

    def __init__(self):
        self.cfg = get_config()
        self.action_history: List[Action] = []
        self._action_count = 0

    async def decide(self, predictions: List[Any]) -> List[Action]:
        """Decide on actions based on predictions/scores.

        Args:
            predictions: List of prediction dicts or objects with
                         probability, target, id, and risk attributes.

        Returns:
            List of Action dataclasses.
        """
        actions: List[Action] = []
        max_actions = self.cfg.v8_autonomous.max_actions_per_cycle

        if not predictions:
            logger.info("No predictions to evaluate — no actions taken")
            return actions

        for p in predictions[:max_actions]:
            probability = float(_extract(p, "probability", 0.0))
            risk = float(_extract(p, "risk", 0.0))
            target = str(_extract(p, "target", "unknown"))
            pred_id = str(_extract(p, "id", ""))
            pred_type = str(_extract(p, "prediction_type", "unknown"))

            score = max(probability, risk)
            logger.debug(
                "Evaluating prediction %s target=%s type=%s score=%.2f",
                pred_id, target, pred_type, score,
            )

            if score > 0.8:
                actions.append(Action(
                    type="isolate",
                    target=target,
                    risk_score=score,
                    description=f"High-risk target {target} — isolate and deploy decoy",
                    priority="critical",
                    prediction_id=pred_id,
                ))
                logger.warning("CRITICAL action: isolate %s (score=%.2f)", target, score)
            elif score > 0.6:
                actions.append(Action(
                    type="monitor",
                    target=target,
                    risk_score=score,
                    description=f"Elevated risk on {target} — increase monitoring",
                    priority="high",
                    prediction_id=pred_id,
                ))
                logger.info("HIGH action: monitor %s (score=%.2f)", target, score)
            elif score > 0.3:
                actions.append(Action(
                    type="log",
                    target=target,
                    risk_score=score,
                    description=f"Notable activity on {target} — log for analysis",
                    priority="medium",
                    prediction_id=pred_id,
                ))
                logger.info("MEDIUM action: log %s (score=%.2f)", target, score)
            else:
                logger.debug("Low risk %s (score=%.2f) — no action", target, score)

        self.action_history.extend(actions)
        self._action_count += len(actions)
        logger.info("Autonomous cycle complete: %d action(s) issued", len(actions))
        return actions

    @property
    def total_actions_issued(self) -> int:
        return self._action_count
