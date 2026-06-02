#!/usr/bin/env python3
"""Compatibility wrapper for the renamed antivenom remediation generator."""
from __future__ import annotations

import sys

from antivenom import *  # noqa: F401,F403
from antivenom import main as _main


if __name__ == "__main__":
    sys.exit(_main())
