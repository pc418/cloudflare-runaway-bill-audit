#!/usr/bin/env python3
"""cloudflare-runaway-bill-audit entry point: `python3 scripts/audit.py scan <project>`."""

import sys
from pathlib import Path

# Before importing the package: the skill may be installed inside the project it scans
# (e.g. .claude/skills/), and the scanner must not leave __pycache__ there.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from nobill.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
