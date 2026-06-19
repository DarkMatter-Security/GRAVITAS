"""GRAVITAS entry point: python -m gravitas [command]

Part of the OmniGRAVITAS Fusion Platform.
DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

import sys
import logging
from . import __version__, __description__, VERSION_CODENAME

# ─── Pure ASCII banner (console-safe) ──────────────────────────
S = " "  # shortcut for banner building

_v = __version__
_c = VERSION_CODENAME
BANNER = f"""
+{'='*78}+
|{' '*78}|
|{' '*30}G R A V I T A S{' '*30}|
|{' '*78}|
|{' '*12}Inference-Based Reconnaissance & Predictive Intelligence Platform{' '*12}|
|{' '*78}|
|{' '*30}T H E   F U S I O N{' '*27}|
|{' '*78}|
|{' '*27}O M N I G R A V I T A S{' '*27}|
|{' '*12}GRAVITAS Intelligence Pipeline  +  OmniPentestX Offensive Engine{' '*12}|
|{' '*78}|
+{'='*78}+
|{' '*78}|
|{' '*4}Version: {_v} [{_c}]  +  OmniPentestX v1.0.0 [OmniForce]{' '*4}|
|{' '*4}Organization: DarkMatter Security{' '*47}|
|{' '*4}DarkMatter Security -- Invisible Influence / Indirect Intelligence{' '*20}|
|{' '*78}|
+{'='*78}+
"""


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        _safe_print(BANNER)
        print_usage()
        return

    if sys.argv[1] in ("-v", "--version"):
        print(f"GRAVITAS v{__version__} [{VERSION_CODENAME}]")
        return

    command = sys.argv[1].lower()

    if command == "ingest":
        from .v1_ingestion import run_ingestion
        run_ingestion()
    elif command == "pipeline":
        from .core.pipeline import run_pipeline
        run_pipeline()
    elif command == "v1":
        from .v1_ingestion import run_ingestion
        run_ingestion()
    elif command == "status":
        show_status()
    elif command == "omnigravitas":
        _launch_omnigravitas()
    else:
        print(f"Unknown command: {command}")
        print_usage()


def print_usage() -> None:
    """Print usage information."""
    print(f"""
{S*4}GRAVITAS v{__version__} -- {__description__}
{S*4}OmniGRAVITAS Fusion Platform -- DarkMatter Security

{S*4}USAGE:
{S*8}python -m gravitas <command>

{S*4}COMMANDS:
{S*8}ingest          Run V1: Data Ingestion pipeline
{S*8}pipeline        Run full V1-V8 pipeline
{S*8}v1              Run V1 Data Ingestion only
{S*8}status          Show GRAVITAS system status
{S*8}omnigravitas    Launch the OmniGRAVITAS fusion CLI
{S*8}help            Show this message

{S*4}ARCHITECTURE ROADMAP:
{S*8}V1: Data Ingestion      [ACTIVE]
{S*8}V2: Processing          [ACTIVE]
{S*8}V3: Inference           [ACTIVE]
{S*8}V4: Graph               [ACTIVE]
{S*8}V5: Probability         [ACTIVE]
{S*8}V6: Temporal            [ACTIVE]
{S*8}V7: Digital Twin        [ACTIVE]
{S*8}V8: Autonomous Engine   [ACTIVE]

{S*4}EXAMPLES:
{S*8}python -m gravitas ingest
{S*8}python -m gravitas status
{S*8}python -m gravitas omnigravitas
""")


def show_status() -> None:
    """Show system status with OmniGRAVITAS banner."""
    _safe_print(BANNER)
    sep = "=" * 60
    print(f"\n{S*4}{sep}")
    print(f"{S*4}  System Status:  INITIALIZED")
    print(f"{S*4}  Version:        GRAVITAS v{__version__}  +  OmniPentestX v1.0.0")
    print(f"{S*4}  Codename:       {VERSION_CODENAME}")
    print(f"{S*4}  Organization:   DarkMatter Security")
    print(f"{S*4}{sep}")
    print(f"\n{S*4}Engines:")
    print(f"{S*6}V1: Data Ingestion      [ACTIVE]   -- Collect intelligence from all sources")
    print(f"{S*6}V2: Processing           [ACTIVE]   -- Normalize, enrich, structure data")
    print(f"{S*6}V3: Inference            [ACTIVE]   -- Pattern recognition & threat detection")
    print(f"{S*6}V4: Graph                [ACTIVE]   -- Knowledge graph of entities & relationships")
    print(f"{S*6}V5: Probability          [ACTIVE]   -- Risk scoring & predictive likelihood")
    print(f"{S*6}V6: Temporal             [ACTIVE]   -- Time-series analysis & trend prediction")
    print(f"{S*6}V7: Digital Twin         [ACTIVE]   -- Virtual representation of target environment")
    print(f"{S*6}V8: Autonomous Engine    [ACTIVE]   -- Self-acting defense & deception deployment")
    print(f"\n{S*4}Bridge: OmniPentestX <-> GRAVITAS [ACTIVE]")
    print()


def _safe_print(text: str) -> None:
    """Print text with fallback for Unicode encoding errors."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback: encode to ASCII with replacement
        print(text.encode('ascii', errors='replace').decode('ascii'))


def _launch_omnigravitas() -> None:
    """Launch the OmniGRAVITAS fusion CLI interactive mode."""
    _safe_print(BANNER)
    print(f"{S*4}Launching OmniGRAVITAS Fusion Shell...\n")

    try:
        from omnipentestx.interfaces.cli import cli_main
        print(f"{S*4}[+] Fusing GRAVITAS intelligence pipeline with OmniPentestX offensive engine...")
        print(f"{S*4}[+] Both systems initialized. Welcome to OmniGRAVITAS.\n")
        cli_main()
    except ImportError:
        print(f"{S*4}[!] OmniPentestX not installed. Run: pip install omnipentestx")
        print(f"{S*4}[!] Falling back to GRAVITAS standalone mode.")
        from .core.pipeline import run_pipeline
        run_pipeline()


if __name__ == "__main__":
    main()
