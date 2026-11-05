"""Compatibility wrapper: `python -m scripts.validate_detections [--live]` runs ndctl."""
from __future__ import annotations

import sys

from ndctl.cli import main

if __name__ == "__main__":
    sys.exit(main(["test" if "--live" in sys.argv else "validate"]))
