#!/usr/bin/env python3
"""Compatibility entry point; install/copy the complete repository, not this file alone."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from http_ctl.server import main
if __name__ == '__main__':
    main()
