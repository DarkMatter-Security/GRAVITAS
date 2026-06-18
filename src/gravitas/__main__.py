"""GRAVITAS entry point: python -m gravitas [command]

Part of the OmniGRAVITAS Fusion Platform.
DarkMatter Security — Invisible Influence / Indirect Intelligence.
"""

import sys
import logging
from . import __version__, __description__, VERSION_CODENAME


BANNER = f"""
{" " * 4}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{" " * 4}▓▓{" " * 70}▓▓
{" " * 4}▓▓{" " * 13}███████╗ ██████╗  ██████╗ ███╗   ██╗███████╗{" " * 13}▓▓
{" " * 4}▓▓{" " * 13}██╔════╝██╔═══██╗██╔════╝ ████╗  ██║██╔════╝{" " * 13}▓▓
{" " * 4}▓▓{" " * 13}█████╗  ██║   ██║██║  ███╗██╔██╗ ██║█████╗  {" " * 13}▓▓
{" " * 4}▓▓{" " * 13}██╔══╝  ██║   ██║██║   ██║██║╚██╗██║██╔══╝  {" " * 13}▓▓
{" " * 4}▓▓{" " * 13}██║     ╚██████╔╝╚██████╔╝██║ ╚████║███████╗{" " * 13}▓▓
{" " * 4}▓▓{" " * 13}╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝{" " * 13}▓▓
{" " * 4}▓▓{" " * 70}▓▓
{" " * 4}▓▓{" " * 8}████████╗██╗  ██╗███████╗    ███████╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗{" * 1}▓▓
{" " * 4}▓▓{" " * 8}╚══██╔══╝██║  ██║██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝██║██╔═══██╗████╗  ██║{" * 1}▓▓
{" " * 4}▓▓{" " * 8}   ██║   ███████║█████╗      █████╗   ╚████╔╝ █████╗  ██║██║   ██║██╔██╗ ██║{" * 1}▓▓
{" " * 4}▓▓{" " * 8}   ██║   ██╔══██║██╔══╝      ██╔══╝    ╚██╔╝  ██╔══╝  ██║██║   ██║██║╚██╗██║{" * 1}▓▓
{" " * 4}▓▓{" " * 8}   ██║   ██║  ██║███████╗    ███████╗   ██║   ███████╗██║╚██████╔╝██║ ╚████║{" * 1}▓▓
{" " * 4}▓▓{" " * 8}   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝{" * 1}▓▓
{" " * 4}▓▓{" " * 70}▓▓
{" " * 4}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{" " * 4}▓▓{" " * 35}OmniGRAVITAS{" " * 35}▓▓
{" " * 4}▓▓{" " * 10}{__description__}{" " * 10}▓▓
{" " * 4}▓▓{" " * 5}GRAVITAS v{__version__} [{VERSION_CODENAME}]  +  OmniPentestX v1.0.0 [OmniForce]{" " * 5}▓▓
{" " * 4}▓▓{" " * 70}▓▓
{" " * 4}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
{" " * 4}DarkMatter Security — Invisible Influence / Indirect Intelligence
{" " * 4}Built by AntiSyntax.protocol CREW — Happy Birthday my BrotherBear! 🎂
"""


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(BANNER)
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
{" " * 4}GRAVITAS v{__version__} — {__description__}
{" " * 4}OmniGRAVITAS Fusion Platform — DarkMatter Security

{" " * 4}USAGE:
{" " * 8}python -m gravitas <command>

{" " * 4}COMMANDS:
{" " * 8}ingest          Run V1: Data Ingestion pipeline
{" " * 8}pipeline        Run full V1-V8 pipeline
{" " * 8}v1              Run V1 Data Ingestion only
{" " * 8}status          Show GRAVITAS system status
{" " * 8}omnigravitas    Launch the OmniGRAVITAS fusion CLI
{" " * 8}help            Show this message

{" " * 4}ARCHITECTURE ROADMAP:
{" " * 8}V1: Data Ingestion      [ACTIVE]
{" " * 8}V2: Processing          [ACTIVE]
{" " * 8}V3: Inference           [ACTIVE]
{" " * 8}V4: Graph               [ACTIVE]
{" " * 8}V5: Probability         [ACTIVE]
{" " * 8}V6: Temporal            [ACTIVE]
{" " * 8}V7: Digital Twin        [ACTIVE]
{" " * 8}V8: Autonomous Engine   [ACTIVE]

{" " * 4}EXAMPLES:
{" " * 8}python -m gravitas ingest
{" " * 8}python -m gravitas status
{" " * 8}python -m gravitas omnigravitas
""")


def show_status() -> None:
    """Show system status with OmniGRAVITAS banner."""
    print(BANNER)
    print(f"\n{' ' * 4}╔{'═' * 60}╗")
    print(f"{' ' * 4}║  System Status: {'✓ INITIALIZED':<51}║")
    print(f"{' ' * 4}║  Version: GRAVITAS v{__version__:<18}  +  OmniPentestX v1.0.0  ║")
    print(f"{' ' * 4}║  Codename: {VERSION_CODENAME:<44}║")
    print(f"{' ' * 4}║  Organization: DarkMatter Security{' ' * 37}║")
    print(f"{' ' * 4}╚{'═' * 60}╝")
    print(f"\n{' ' * 4}Engines:")
    print(f"{' ' * 6}V1: Data Ingestion      [{'✓' if True else ' '}]  —  Collect intelligence from all sources")
    print(f"{' ' * 6}V2: Processing           [{'✓' if True else ' '}]  —  Normalize, enrich, structure data")
    print(f"{' ' * 6}V3: Inference            [{'✓' if True else ' '}]  —  Pattern recognition & threat detection")
    print(f"{' ' * 6}V4: Graph                [{'✓' if True else ' '}]  —  Knowledge graph of entities & relationships")
    print(f"{' ' * 6}V5: Probability          [{'✓' if True else ' '}]  —  Risk scoring & predictive likelihood")
    print(f"{' ' * 6}V6: Temporal             [{'✓' if True else ' '}]  —  Time-series analysis & trend prediction")
    print(f"{' ' * 6}V7: Digital Twin         [{'✓' if True else ' '}]  —  Virtual representation of target environment")
    print(f"{' ' * 6}V8: Autonomous Engine    [{'✓' if True else ' '}]  —  Self-acting defense & deception deployment")
    print(f"\n{' ' * 4}Bridge: OmniPentestX ↔ GRAVITAS [{'✓' if True else ' '}]")
    print()


def _launch_omnigravitas() -> None:
    """Launch the OmniGRAVITAS fusion CLI interactive mode."""
    print(BANNER)
    print(f"{' ' * 4}Launching OmniGRAVITAS Fusion Shell...\n")

    try:
        from omnipentestx.interfaces.cli import cli_main
        print(f"{' ' * 4}[+] Fusing GRAVITAS intelligence pipeline with OmniPentestX offensive engine...")
        print(f"{' ' * 4}[+] Both systems initialized. Welcome to OmniGRAVITAS.\n")
        cli_main()
    except ImportError:
        print(f"{' ' * 4}[!] OmniPentestX not installed. Run: pip install omnipentestx")
        print(f"{' ' * 4}[!] Falling back to GRAVITAS standalone mode.")
        from .core.pipeline import run_pipeline
        run_pipeline()


if __name__ == "__main__":
    main()
