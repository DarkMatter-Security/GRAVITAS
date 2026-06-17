"""GRAVITAS entry point: python -m gravitas [command]"""

import sys
from . import __version__, __description__, VERSION_CODENAME


BANNER = r"""
  +-----------------------------------------------------------------+
  |                    G R A V I T A S                               |
  |  Inference-Based Reconnaissance & Predictive Intelligence        |
  |                                                                  |
  |     ####   #####  #####  ##    ## ##  ########  #####            |
  |    ##     ##   ## ##  ## ##    ## ##    ##    ##   ##            |
  |    ## ### ######  #####  ##    ## ##    ##    #######            |
  |    ##  ## ##   ## ##  ## ##    ## ##    ##    ##   ##            |
  |     #####  ##   ## ##  ##  ######  ##    ##    ##   ##           |
  |                                                                  |
  |  Dark Matter Security - Invisible Influence / Indirect Intel     |
  |  Version {version:<15}                            |
  +-----------------------------------------------------------------+
""".format(version=__version__)


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
    else:
        print(f"Unknown command: {command}")
        print_usage()


def print_usage() -> None:
    """Print usage information."""
    print(f"""
GRAVITAS v{__version__} - {__description__}

USAGE:
    python -m gravitas <command>

COMMANDS:
    ingest         Run V1: Data Ingestion pipeline
    pipeline       Run full V1-V8 pipeline
    v1             Run V1 Data Ingestion only
    status         Show GRAVITAS system status
    help           Show this message

ARCHITECTURE ROADMAP:
    V1: Data Ingestion      [ACTIVE]
    V2: Processing           [STUB]
    V3: Inference            [STUB]
    V4: Graph                [STUB]
    V5: Probability          [STUB]
    V6: Temporal             [STUB]
    V7: Digital Twin         [STUB]
    V8: Autonomous Engine    [STUB]

EXAMPLES:
    python -m gravitas ingest
    python -m gravitas status
""")


def show_status() -> None:
    """Show system status."""
    print(BANNER)
    print("  System Status: INITIALIZED")
    print(f"  Version: {__version__}")
    print(f"  Codename: {VERSION_CODENAME}")
    print("  Phases:")
    print("    V1: Data Ingestion      [READY]")
    print("    V2: Processing          [STUB]")
    print("    V3: Inference           [STUB]")
    print("    V4: Graph               [STUB]")
    print("    V5: Probability         [STUB]")
    print("    V6: Temporal            [STUB]")
    print("    V7: Digital Twin        [STUB]")
    print("    V8: Autonomous Engine   [STUB]")


if __name__ == "__main__":
    main()
