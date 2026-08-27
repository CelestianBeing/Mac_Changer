"""Entry point: ``python -m privacykit``."""

import sys

from .gui.app import run

if __name__ == "__main__":
    sys.exit(run())
