"""Standalone entry point for the portable transaction kernel.

Fixture-only program until a privileged native adapter performs real lifecycle
operations and validates quiescence/service health. No machine installation.
"""
from installer_engine.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
