#!/usr/bin/env python3
"""Compatibility wrapper for the renamed rattlesnake scanner."""
from __future__ import annotations

import sys

from rattlesnake import *  # noqa: F401,F403
from rattlesnake import main as _main


if __name__ == "__main__":
    sys.exit(_main())
