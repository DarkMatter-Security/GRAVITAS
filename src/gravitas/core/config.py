"""Global configuration for GRAVITAS platform."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

# ─── Default Paths ───────────────────────────────────────────────
DEFAULT_CONFIG_DIR = Path.home() / ".gravitas"
DEFAULT_DB_PATH = DEFAULT_CONFIG_DIR / "gravitas.db"
DEFAULT_LOG_DIR = DEFAULT_CONFIG_DIR / "logs"
DEFAULT_DATA_DIR = DEFAULT_CONFIG_DIR / "data"
DEFAULT_MODEL_DIR = DEFAULT_CONFIG_DIR / "models"


@dataclass
class IngestionConfig:
    """V1: Data Ingestion settings."""
    enabled: bool = True
    poll_interval: int = 60  # seconds
    max_batch_size: int = 1000
    sources: List[str] = field(default_factory=lambda: ["file", "api", "omnipentestx"])
    omnipentestx_db_path: str = str(Path.home() / ".omnipentestx" / "omnipentestx.db")
    file_watch_dirs: List[str] = field(default_factory=list)


@dataclass
class ProcessingConfig:
    """V2: Processing settings."""
    enabled: bool = True
    normalize_text: bool = True
    extract_entities: bool = True
    deduplicate: bool = True
    enrichment_sources: List[str] = field(default_factory=list)


@dataclass
class InferenceConfig:
    """V3: Inference settings."""
    enabled: bool = False
    model_path: str = ""
    confidence_threshold: float = 0.7
    use_local_llm: bool = False


@dataclass
class GraphConfig:
    """V4: Graph settings."""
    enabled: bool = False
    backend: str = "networkx"  # networkx, neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""


@dataclass
class ProbabilityConfig:
    """V5: Probability & Risk scoring."""
    enabled: bool = False
    risk_threshold_high: float = 0.8
    risk_threshold_medium: float = 0.5
    enable_monte_carlo: bool = False


@dataclass
class TemporalConfig:
    """V6: Temporal analysis."""
    enabled: bool = False
    window_size: int = 3600  # 1 hour in seconds
    trend_sensitivity: float = 0.3


@dataclass
class DigitalTwinConfig:
    """V7: Digital Twin settings."""
    enabled: bool = False
    sync_interval: int = 300
    fidelity: str = "high"  # low, medium, high


@dataclass
class AutonomousConfig:
    """V8: Autonomous Engine settings."""
    enabled: bool = False
    auto_respond: bool = False
    deploy_decoys: bool = False
    max_actions_per_cycle: int = 5
    require_approval: bool = True


@dataclass
class GRAVITASConfig:
    """Root configuration for GRAVITAS platform."""
    # System
    debug: bool = False
    log_level: str = "INFO"
    data_dir: str = str(DEFAULT_DATA_DIR)
    
    # Pipeline stages
    v1_ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    v2_processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    v3_inference: InferenceConfig = field(default_factory=InferenceConfig)
    v4_graph: GraphConfig = field(default_factory=GraphConfig)
    v5_probability: ProbabilityConfig = field(default_factory=ProbabilityConfig)
    v6_temporal: TemporalConfig = field(default_factory=TemporalConfig)
    v7_digital_twin: DigitalTwinConfig = field(default_factory=DigitalTwinConfig)
    v8_autonomous: AutonomousConfig = field(default_factory=AutonomousConfig)


# ─── Global Config Singleton ─────────────────────────────────────

_config: Optional[GRAVITASConfig] = None


def load_config(path: Optional[str] = None) -> GRAVITASConfig:
    """Load configuration from file or create defaults."""
    global _config
    
    config_path = Path(path) if path else DEFAULT_CONFIG_DIR / "config.yaml"
    
    if config_path.exists():
        import yaml
        with open(config_path) as f:
            data = yaml.safe_load(f)
        _config = _dict_to_config(data)
    else:
        _config = GRAVITASConfig()
        # Save defaults
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        save_config(_config)
    
    return _config


def get_config() -> GRAVITASConfig:
    """Get the global configuration."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def save_config(config: GRAVITASConfig, path: Optional[str] = None) -> None:
    """Save configuration to file."""
    config_path = Path(path) if path else DEFAULT_CONFIG_DIR / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    
    import yaml
    with open(config_path, "w") as f:
        yaml.dump(config_to_dict(config), f, default_flow_style=False)


def config_to_dict(config: GRAVITASConfig) -> Dict[str, Any]:
    """Convert config dataclass to dictionary."""
    d = {}
    for key, value in asdict(config).items():
        if isinstance(value, dict):
            d[key] = value
        else:
            d[key] = value
    return d


def _dict_to_config(data: Dict[str, Any]) -> GRAVITASConfig:
    """Convert dictionary back to config dataclass (recursive)."""

    _CONFIG_CLASSES = {
        "v1_ingestion": IngestionConfig,
        "v2_processing": ProcessingConfig,
        "v3_inference": InferenceConfig,
        "v4_graph": GraphConfig,
        "v5_probability": ProbabilityConfig,
        "v6_temporal": TemporalConfig,
        "v7_digital_twin": DigitalTwinConfig,
        "v8_autonomous": AutonomousConfig,
    }

    kwargs = {}
    for k, v in data.items():
        if k not in GRAVITASConfig.__dataclass_fields__:
            continue
        cls = _CONFIG_CLASSES.get(k)
        if cls and isinstance(v, dict):
            # Reconstruct nested dataclass
            kwargs[k] = cls(**{
                sub_k: sub_v for sub_k, sub_v in v.items()
                if sub_k in cls.__dataclass_fields__
            })
        else:
            kwargs[k] = v
    return GRAVITASConfig(**kwargs)
